<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/lockup-reverse.svg">
    <img src="assets/brand/lockup.svg" width="340" alt="bare server">
  </picture>
</p>

<p align="center">
  A minimal static-file web server with built-in TLS termination,
  in a single static binary with no runtime dependencies.
</p>

<p align="center">
  <a href="../../actions/workflows/ci.yml"><img src="../../actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-0B0D0F" alt="MIT">
  <img src="https://img.shields.io/badge/rust-1.85%2B-C4451E" alt="Rust 1.85+">
</p>

The design is one idea taken seriously: **do the work at boot, not per request.**
Every file under a document root is read, compressed, and baked into a complete
HTTP response — headers and body in one contiguous buffer — before the listeners
bind. Serving a request is then a hash lookup, a short header scan, and one
`write_all`. No per-request allocation, no per-request compression, and — under
the default `storage = memory` — no filesystem access.

---

## Quick start

```sh
cargo build --release --locked
cp server.conf.example server.conf
./target/release/bare-server server.conf
```

A minimal config is one `site` block:

```
listen = [::]:443
listen_http = [::]:80

site example.com, www.example.com {
    root = /var/www/example
    cert = /etc/bare-server/tls/example/cert.pem
    key  = /etc/bare-server/tls/example/key.pem
}
```

For a local run, `./gen-cert.sh` writes a self-signed pair and the end of
[`server.conf.example`](server.conf.example) has a ready-made localhost block.

> **Requires Rust 1.85+, and Unix only** — Linux, macOS, and the BSDs. The ACME
> token read uses `O_NOFOLLOW` and `st_nlink` directly, so the crate does not
> build on Windows. CI builds x86-64 and ARM Linux (glibc and musl), armv7 musl,
> FreeBSD, and both macOS architectures.

## Documentation

| Guide | Covers |
| --- | --- |
| [Configuration](docs/CONFIGURATION.md) | Every directive, where each is allowed, redirect rules, canonical URLs, per-site overrides |
| [Deployment](docs/DEPLOYMENT.md) | Docker and systemd, TLS key permissions and ACME renewal, hot reload, operating notes |
| [Contributing](CONTRIBUTING.md) | Build, test, code style, release process |
| [Security](SECURITY.md) | Reporting policy, scope, security-relevant design decisions |
| [Brand](BRAND.md) | The mark, palette, type, naming and voice, and the CLI banner |

## How it works

### The response path

**Precomputed responses.** Header and body live in one buffer per encoding
variant, so a response is a single write — one TLS record, one syscall.

**Precomputed compression.** At boot every compressible file is compressed with
brotli (q11) and gzip (level 9), each stored as a complete ready-to-send
response. Requests are served by `Accept-Encoding` at zero per-request
compression cost. Already-compressed types (images, video, fonts) are skipped,
and a variant is kept only if it is actually smaller. Responses carry
`Vary: Accept-Encoding`.

**Memory or disk storage.** `storage = memory` (the default) holds every file in
RAM as above — the fastest path, but resident memory scales with the site.
`storage = disk` keeps only a small index in RAM and snapshots bodies plus
gzip/brotli sidecars into `disk_cache`, streaming them at serve time so the OS
page cache does the buffering. RAM then stays roughly constant regardless of
site size. Headers are identical either way; only where the body lives differs.

### TLS

**TLS 1.2 and 1.3** via [rustls](https://github.com/rustls/rustls) with the
`ring` provider — pure Rust, no OpenSSL, links cleanly as a fully static musl
binary. Forward-secret AEAD suites only. Certificates are loaded as-is — RSA or
ECDSA, from any CA.

Session resumption turns a full handshake into a cheap reconnect, and TLS 1.3
0-RTT early data lets a resuming client send its request in the first flight.
0-RTT data is replayable, which is safe here because the server only performs
idempotent, side-effect-free `GET` and `HEAD` of public static files.

> Sites are selected by **SNI**, so a client connecting to a bare IP address
> sends no SNI and has its handshake refused. Use a hostname.

### Routing

**Clean (extensionless) URLs.** `/about` and `/about/` both serve `about.html`;
`/` and `/dir/` serve `index.html`. Resolution is exact → `.html` →
`/index.html`, all as in-memory lookups against a table built at boot, so a
request path never becomes a filesystem path and adds no traversal surface.
Optionally, `canonical_urls = on` folds the `.html` spellings onto the directory
form with a `301`; the fold is computed on the decoded path, so every spelling of
a URL lands on the same canonical one.

**Virtual hosts with per-site config.** Each host is a `site` block with its own
root, certificate, and — where it makes sense — its own cache, compression, and
header settings. A block with no root is a redirect-only host.

**Redirect rules.** Exact paths, `/prefix/*` with a capture, and a whole-host
catch-all. Most specific wins regardless of the order written, so matching is a
hash lookup plus a short scan, never a regex.

### Hardening

The HTTP/1.1 parser is strict by construction: CRLF line breaks only (a bare LF,
obs-fold, or whitespace in a field name is a `400`), exactly one `Host`, a
declared body refused, and an exact three-field request line — closing the
request-smuggling surface.

Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, HSTS, and an optional CSP) go out on
every response, including errors, and are tunable per site. A request whose
`Host` disagrees with the connection's SNI is refused, so one site's certificate
cannot front another's content.

Wall-clock deadlines bound the handshake, the request head, and connection
lifetime, and they are enforced at the socket *below* rustls — a TLS read does
not return until a whole record has arrived, so a deadline checked only between
requests never fires against a client dribbling bytes inside one. An in-flight
response is held to a minimum transfer rate rather than a "some byte moved" test,
which one byte every few seconds satisfies indefinitely. A per-source-IP
connection cap keeps one peer from taking every slot, and both it and
`max_response_secs` are re-read on reload, so neither needs a restart to change
while a flood is in progress.

### Operations

**Hot reload.** A watcher polls the config file, each document root, and each
certificate every 2 seconds and swaps in a new runtime once a change has
settled. Content, certificates, sites, redirect rules, and even listen addresses
change without a restart, and an in-flight request always finishes against the
snapshot it started with. A config that fails to load leaves the running server
serving the previous one.

## Performance

Reproduce all of this with [`bench/bench.sh`](bench/bench.sh), which builds the
server, synthesises a fixed corpus, starts it, measures, and tears it down:

```sh
./bench/bench.sh            # everything
./bench/bench.sh --quick    # shorter load phases
./bench/bench.sh --no-load  # deterministic measurements only
```

### Compression

Depends only on the corpus and the build, so these reproduce on any machine:

| File | Identity | gzip | brotli | Saved (br) |
| --- | ---: | ---: | ---: | ---: |
| `index.html` | 9,217 B | 1,548 B | 1,314 B | 86% |
| `app.css` (40 KB) | 40,043 B | 5,826 B | 4,512 B | 89% |
| `app.js` (180 KB) | 180,024 B | 33,319 B | 25,874 B | 86% |
| `photo.png` | 200,000 B | — | — | skipped, already compressed |
| `tiny.txt` | 3 B | — | — | skipped, under `min_compress_bytes` |

### Build and footprint

| | |
| --- | --- |
| Static binary (aarch64 musl) | ~2.3 MB stripped (~1.2 MB compressed) |
| Docker image (`FROM scratch`) | ~2.4 MB — essentially just the binary |
| Boot to first served byte | ~1.0–1.8 s for 26 files / 809 KB, brotli q11 |
| Resident memory | 51 MiB for a 1.0 MB cache, `storage = memory` |

Exact binary size varies a little by target and toolchain. Release archives and
CI artifacts are compressed, so a download of roughly half that size is the same
binary, not a different build.

### Throughput

**Machine-specific.** One run on an Apple M3 Pro (12 cores, macOS 27) over
loopback, `wrk` with 4 threads and 64 connections for 10 s — with the load
generator competing for the same CPUs. This is a shape, not a score; do not
compare it against numbers taken on a different host.

| Phase | Requests/s | p50 | p99 | Wire throughput |
| --- | ---: | ---: | ---: | ---: |
| 9 KB HTML, identity | 156,700 | 372 µs | 683 µs | 1.41 GB/s |
| 9 KB HTML, brotli | 164,404 | 368 µs | 523 µs | 281 MB/s |
| 180 KB JS, identity | 23,033 | 2.68 ms | 3.88 ms | 3.87 GB/s |
| 404 (not found) | 119,609 | 462 µs | 2.29 ms | 48 MB/s |
| `:80` → `:443` 301 | 161,390 | 375 µs | 606 µs | 57 MB/s |

Two things worth reading off that table. Serving brotli is *slightly faster*
than identity while moving a fifth of the bytes — the variant is precompressed,
so the only difference at request time is how much goes on the wire. And a 404
is not free: it is built per request rather than looked up, which is why it
trails a cache hit.

### Connection setup

The cost that dominates when clients do not reuse connections:

| | |
| --- | --- |
| Full TLS handshake | 2.74 ms median, 3.19 ms p90 (n=50, RSA-2048) |
| New connection per request | 15,246 req/s |
| Reused connection | 156,700 req/s |

That ~10× gap is the entire reason the server enables session resumption and
0-RTT early data.

## What it does not do

No CGI, no reverse proxying, no directory listings, no HTTP/2 or HTTP/3, no
request logging, no rate limiting beyond the connection caps, no `Range`
requests. `GET` and `HEAD` only. If you need any of those, this is the wrong
server — that is the point of the name.

## Design notes

**Why not pre-encrypt the files at boot too?** It is impossible, and it would
not help. TLS keys are negotiated per connection, and each record's nonce is
bound to its sequence number within that connection's stream — there is no key
at boot, and bytes encrypted for one client are useless to (and rejected by)
another. That per-connection uniqueness is exactly what prevents replay. It also
would not buy anything: AEAD-encrypting a small response with AES-NI costs a
fraction of a microsecond. The useful version of the idea — precomputing the
*plaintext* response and its *compressed* forms — is what the server does.

**Why thread-per-connection?** The hot path is a lookup and a write, so a
connection thread spends nearly all of its life blocked in a syscall. A 128 KB
reserved stack and a semaphore capping concurrency at 1024 keep the worst case
bounded, and a panic in one connection stays contained to its own thread instead
of aborting the process.

**Why is the release profile `opt-level = "s"`?** The request hot path is a
hashmap lookup, a header scan, and one `write_all` — the real CPU work happens
inside `ring`'s hand-written assembly, which `opt-level` does not touch.
Optimizing for size instead measured 12.8% smaller on a static musl build. Boot
compression is the one place where speed does buy something, so `brotli` and
`miniz_oxide` are pinned to `opt-level = 3` individually.

## License

MIT — see [LICENSE](LICENSE).
