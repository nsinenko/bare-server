# Deployment guide

A release build is a single, fully static binary (~2.3 MB, measured on
aarch64 musl) with no libc and no runtime dependencies. There are two supported ways to run it — a `scratch`
container or a systemd unit on the host. Pick whichever suits your host; they
differ only in how the process gets permission to bind ports 80 and 443.

## Building

```sh
cargo build --release --locked
```

`--locked` is deliberate: without it, cargo re-resolves every dependency to the
newest semver-compatible release at build time, so two builds of the same source
can ship different code — including build scripts (`ring`, `cc`) that execute
during the build.

For a **fully static musl binary**, which is what both deployment options
assume:

```sh
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --locked --target x86_64-unknown-linux-musl
```

The Docker build does this for you.

## Option 1: Container (Docker)

The image is a `scratch` container holding just the binary — no shell, no CA
store, no package manager, nothing to patch but the binary itself.

```sh
docker build -t bare-server .
```

A non-root process cannot bind ports below 1024, and dropping to an unprivileged
uid clears the `NET_BIND_SERVICE` capability that Docker's default set grants
only to root. Rather than hand the process that capability, lower the threshold
host-wide:

```sh
echo 'net.ipv4.ip_unprivileged_port_start=80' > /etc/sysctl.d/99-bare-server.conf
sysctl --system
```

> **Understand what this trades away.** The sysctl is a *floor*, not an
> allowlist: it makes **every** port from 80 up bindable by **every** local uid,
> IPv6 included, permanently, for the whole host. On a single-purpose box with no
> other unprivileged accounts that costs nothing. On a host that has (or later
> gains) a CI runner, a monitoring agent, or any other unprivileged service, any
> of them can race for `:80` the next time bare-server restarts — and whoever
> holds `:80` can answer an ACME `http-01` challenge and be issued a valid
> certificate for your domains. Worse, bare-server treats a failed bind as fatal,
> so with `--restart always` a squatted `:80` becomes a restart loop that also
> gives up `:443` on every cycle.
>
> **If that trade is not obviously fine for your host, don't take it.** Drop
> `--network host` and publish the ports instead:
>
> ```sh
> docker run -d --name bare-server --restart always \
>   -p 80:80 -p 443:443 \
>   --read-only --user 1000:1000 \
>   -v /etc/bare-server:/etc/bare-server:ro \
>   -v /var/www:/var/www:ro \
>   bare-server /etc/bare-server/server.conf
> ```
>
> Docker sets `ip_unprivileged_port_start=0` inside a container that has its own
> network namespace, so this binds `:80`/`:443` as uid 1000 with no host sysctl
> and no added capability — the same relaxation, confined to the container. The
> cost is the NAT/userland-proxy hop that `--network host` exists to avoid.
>
> `--cap-add NET_BIND_SERVICE` is *not* an option here: Docker does not expose the
> ambient capability set, and the permitted set is cleared on the transition to a
> non-root uid, so the capability never reaches the process. File capabilities are
> equally unavailable — `setcap` needs a shell the `scratch` image does not have,
> and `COPY --from` does not preserve extended attributes. The systemd unit below
> can do this properly because it runs as PID 1 with an ambient-caps API.

`scratch` has no `/etc/passwd`, so the container user is named numerically. The
image defaults to `1000:1000`; create a matching account on the host so it can
read a root-written key over the read-only mount, and pass `--user` explicitly if
it lands on different ids:

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin bare-server
id bare-server        # note the uid:gid this lands on
```

```sh
docker run -d --name bare-server --restart always \
  --network host \
  --read-only \
  --user 1000:1000 \
  -v /etc/bare-server:/etc/bare-server:ro \
  -v /var/www:/var/www:ro \
  bare-server /etc/bare-server/server.conf
```

Why each flag:

- **`--network host`** binds `[::]:80` and `[::]:443` directly, with no
  userland-proxy or NAT hop in front of every connection.
- **`--user <uid:gid>` with no added capabilities.** The process holds *zero*
  capabilities — but note the privilege was moved to the host, not removed: the
  sysctl above is what lets it bind the ports, and it lets every other local uid
  bind them too. (The systemd option below makes the opposite choice, and a
  better one where it is available.)
- **`--read-only`**, with both mounts `:ro`. The process only reads files and
  opens sockets, so nothing it can touch needs to be writable.
- **The config path is the run argument**, overriding the image default. Point it
  wherever you like — including next to the content, so sites can be added
  without rebuilding the image.

> **Using `storage = disk`?** Then the process *does* need somewhere to write.
> Drop `--read-only` or add a writable mount for `disk_cache`, e.g.
> `--tmpfs` is **not** suitable — it must be real disk — so use
> `-v /var/cache/bare-server:/var/cache/bare-server` and make it writable by the
> container's uid.

## Option 2: Host (systemd)

[`deploy/bare-server.service`](../deploy/bare-server.service) runs the same
binary directly on the host. It binds the privileged ports via
`AmbientCapabilities=CAP_NET_BIND_SERVICE` — no sysctl change — and applies the
same unprivileged-user and read-only-filesystem hardening.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin bare-server

install -m0755 target/release/bare-server /usr/local/bin/bare-server
install -m0644 deploy/bare-server.service /etc/systemd/system/
install -d -m0755 /etc/bare-server
install -m0644 server.conf.example /etc/bare-server/server.conf
# edit /etc/bare-server/server.conf, then:

systemctl daemon-reload
systemctl enable --now bare-server
systemctl status bare-server
```

The unit logs to the journal:

```sh
journalctl -u bare-server -f
```

Two settings in it are load-bearing and worth understanding before you change
them:

- **`LimitNOFILE=16384`.** The concurrency caps in the server (1024 HTTPS + 256
  HTTP connections) allow roughly 1280 sockets held simultaneously, above
  systemd's default 1024 soft limit — `accept()` would start failing with
  `EMFILE` before the anti-DoS cap ever engaged. The headroom also covers the
  listeners and the file descriptors the reload path opens.
- **`StartLimitIntervalSec=300` with `StartLimitBurst=60`.** Every startup error
  is fatal by design (bad config, unreadable certificate, bind failure), and the
  default budget of 5 starts in 10 seconds trips almost immediately at
  `RestartSec=5` — a transient fault such as a root not yet mounted would leave
  the unit permanently failed. `StartLimitIntervalSec` is the *window* systemd
  counts starts over, not a retry duration, so the burst must span it: at one
  start every 5 seconds, 60 starts fill a 300-second window, i.e. it keeps
  retrying for about 5 minutes before giving up.

> **Using `storage = disk`?** `ProtectSystem=strict` makes the whole filesystem
> read-only, so add the cache directory to the unit:
> ```
> ReadWritePaths=/var/cache/bare-server
> ```
> and create it owned by the service user.

## TLS key material

Whichever option you choose, the process runs as an unprivileged user, so each
private key must be readable by that user — and only by that user. ACME tooling
writes keys root-only `0600`, so ownership has to be fixed up after each
issuance:

```sh
install -d -m0750 -o root -g bare-server /etc/bare-server/tls
install -d -m0750 -o root -g bare-server /etc/bare-server/tls/example
install -m0644 -o root -g bare-server /path/to/fullchain.pem /etc/bare-server/tls/example/cert.pem
install -m0640 -o root -g bare-server /path/to/privkey.pem   /etc/bare-server/tls/example/key.pem
```

**Certificate renewal must reproduce that ownership and mode** — for example
from an ACME client's deploy hook (`certbot --deploy-hook`) that copies the pair
and re-applies `chown`/`chmod`.

Do not "fix" an unreadable key by widening it to `0644`: that publishes the
private key to every local user. Leaving it root-only `0600` makes the server
fail to load it. `0640` with group ownership is the setting that works.

### ACME renewal

`/.well-known/acme-challenge/` is exempt from the `force_ssl` upgrade, from all
redirect rules, and from canonical-URL folding, so `http-01` renewal keeps
working no matter how a site is configured. That one path is read from disk per
request — rather than from the in-memory cache — so a challenge token written
after boot is served without a restart.

The path is confined to a `[A-Za-z0-9_-]` token and refuses symlinks at every
level, so it does not reopen the traversal surface that the in-memory design
otherwise closes.

Point your ACME client's webroot at the site's document root. Renewed
certificates are picked up by the watcher within a couple of seconds — no
restart, no reload signal.

## Local testing

For a local run without a real certificate:

```sh
./gen-cert.sh                     # writes a self-signed tls/ pair for localhost
cp server.conf.example server.conf
# uncomment the "local test run" block at the end of server.conf and delete the
# example.com site above it — it binds unprivileged ports and points at ./www
./target/release/bare-server server.conf
```

```sh
curl -skI  https://localhost:8443/
curl -sk -H 'Accept-Encoding: br' -o /dev/null -D- https://localhost:8443/
```

Use the **hostname**, not `127.0.0.1`: sites are selected by SNI, and a
connection to an IP literal carries none, so the handshake is refused with an
`access_denied` alert.

`gen-cert.sh` produces a self-signed certificate for `localhost` only. It is for
local testing and benchmarking — never for anything reachable from the internet.

## Operating notes

**Content changes need no restart.** The watcher polls each document root every
2 seconds and hot-swaps the cache once a change has settled, so an in-flight
request always finishes against the snapshot it started with. Deploy content by
writing it into the root — an `rsync` still in progress is not mistaken for a
finished deploy.

**Config changes need no restart either.** Sites, roots, certificates, redirect
rules, the connection limits (`max_conns_per_ip`, `max_response_secs`), and even
the listen addresses are re-read live. A listener is rebound only if the new
address binds cleanly; otherwise the old one keeps serving and the failure is
logged. **An invalid config never takes effect** — it is logged and discarded,
and the running server keeps serving the previous one.

**Symlinked roots work.** With a release-flip layout (`/srv/www ->
/srv/releases/42`), repointing the symlink is picked up like any other change:
the configured path is re-resolved each tick, so the new release goes live
without a restart. Keep the old release directory in place until the swap has
settled, as you would with any atomic deploy.

**Memory sizing.** In `storage = memory`, resident memory is roughly the sum of
every cached variant. A reload builds the replacement cache before dropping the
old one, so both are resident at peak: size the host for **2× `max_total_bytes`**.
If that is too much, switch to `storage = disk`, where RAM stays roughly
constant regardless of site size.

**Boot time is dominated by brotli.** Compression runs serially before the
listeners bind, and brotli q11 runs at roughly 1 MB/s. On a small or single-core
box, lowering `brotli_quality` to 4–5 is the single biggest startup win, at a
cost of about 5% more bytes on the wire.

**Logging** goes to stderr (and so to the journal under systemd), prefixed with
`bare-server:`. There is no request log — only startup, reload, and error
events.

**Restarting** is only needed to change the binary. `systemctl restart
bare-server`, or `docker restart bare-server`, will briefly refuse connections
while the cache rebuilds.
