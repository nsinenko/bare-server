<!-- Absolute URLs on purpose: `assets/` is excluded from the published crate
     (see Cargo.toml), and a crate's README is immutable once a version is on
     crates.io, so a relative path would render as a broken image there forever. -->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/nsinenko/bare-server/main/assets/brand/lockup-reverse.svg">
    <img src="https://raw.githubusercontent.com/nsinenko/bare-server/main/assets/brand/lockup.svg" width="340" alt="bare server">
  </picture>
</p>

<p align="center">
  A light, fast server for static assets. One static binary, TLS included,
  no runtime dependencies.
</p>

<p align="center">
  <a href="https://github.com/nsinenko/bare-server/actions/workflows/ci.yml"><img src="https://github.com/nsinenko/bare-server/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/bare-server"><img src="https://img.shields.io/crates/v/bare-server?color=C4451E" alt="crates.io"></a>
  <img src="https://img.shields.io/badge/license-MIT-0B0D0F" alt="MIT">
  <img src="https://img.shields.io/badge/rust-1.85%2B-C4451E" alt="Rust 1.85+">
</p>

The server does the work at boot rather than per request. It reads every file
under a document root, compresses it, and builds a complete HTTP response: header
and body in one contiguous buffer. Only then do the listeners bind. A request
costs a hash lookup, a short header scan, and one `write_all`. Nothing allocates
per request, nothing compresses per request, and under the default
`storage = memory` the only path that touches the filesystem is an ACME challenge.

The binary is about 2.2 MB and fully static. On the machine in
[Performance](#performance) a cache hit over TLS sustained 161,775 requests per
second.

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

For a local run, `./gen-cert.sh` writes a self-signed pair. The end of
[`server.conf.example`](server.conf.example) has a ready-made localhost block.

> **Requires Rust 1.85+, and Unix only:** Linux, macOS, and the BSDs. The ACME
> token read uses `O_NOFOLLOW` and `st_nlink` directly, so the crate does not
> build on Windows. CI builds x86-64 and ARM Linux (glibc and musl), armv7 musl,
> FreeBSD, and both macOS architectures.

## Documentation

| Guide | Covers |
| --- | --- |
| [Configuration](https://github.com/nsinenko/bare-server/blob/main/docs/CONFIGURATION.md) | Every directive, where each is allowed, redirect rules, canonical URLs, per-site overrides |
| [Deployment](https://github.com/nsinenko/bare-server/blob/main/docs/DEPLOYMENT.md) | Docker and systemd, TLS key permissions and ACME renewal, hot reload, operating notes |
| [Contributing](CONTRIBUTING.md) | Build, test, code style, release process |
| [Security](SECURITY.md) | Reporting policy, scope, security-relevant design decisions |

## How it works

### The response path

Each encoding variant of each file is one buffer that holds its header and its
body together. A response is therefore one write: one TLS record, one syscall.
The server builds the 4xx and 5xx responses the same way, at boot, with the site's own
security headers already in them. Errors carry `Cache-Control: no-store`, so a
shared cache cannot keep answering 404 for a URL that the site publishes later.

Compression also happens at boot. Every compressible file is compressed with
brotli (q11) and gzip (level 9), and each result is stored as a complete
ready-to-send response. A request selects one by `Accept-Encoding` and pays
nothing to compress it. Already-compressed types (images, video, fonts) are
skipped, and a variant is kept only when it is really smaller. These responses
carry `Vary: Accept-Encoding`.

Storage is memory or disk. `storage = memory`, the default, holds every buffer in
RAM. It is the fastest path, but resident memory grows with the site.
`storage = disk` keeps only a small index in RAM. It snapshots the bodies and the
gzip and brotli sidecars into `disk_cache`, then streams them at serve time, so
the OS page cache buffers them. RAM then stays roughly flat whatever the size of
the site. The headers are identical either way. Only the place the body lives is
different.

### TLS

TLS 1.2 and 1.3 come from [rustls](https://github.com/rustls/rustls) with the
`ring` provider: pure Rust, no OpenSSL, and it links cleanly as a fully static
musl binary. Forward-secret AEAD suites only. The server loads certificates
as-is, RSA or ECDSA, from any CA.

Session resumption turns a full handshake into a cheap reconnect, and TLS 1.3
0-RTT early data lets a client that resumes send its request in the first
flight. 0-RTT data is replayable. That is safe here, because the server only
answers `GET` and `HEAD` for public static files, which have no side effects.

> Sites are selected by **SNI**. A client that connects to a bare IP address
> sends no SNI, and the server refuses the handshake. Use a hostname.

### Routing

URLs need no extension. `/about` and `/about/` both serve `about.html`, and `/`
and `/dir/` serve `index.html`. For a plain URL the server tries the exact path,
then that path plus `.html`. For a URL that ends in `/` it tries
`<url>index.html`, then the path without its slash plus `.html`. A path that names
a directory with an index gets a `301` to the trailing-slash form. Every step is a
lookup in a table built at boot, so a request path never becomes a filesystem path
and adds no traversal surface.

`canonical_urls = on` folds the `.html` spellings onto the directory form with a
`301`. The server computes the fold on the decoded path, so every spelling of a URL
lands on the same canonical one.

Each virtual host is a `site` block with its own root and certificate. Where it
makes sense it also carries its own cache, compression, and header settings. A
block with no root is a redirect-only host.

Redirect rules take three forms: an exact path, `/prefix/*` with a capture, and a
catch-all for the whole host. The most specific rule wins whatever order you
write them in, so a match is a hash lookup plus a short scan. No regex runs.

### Hardening

The HTTP/1.1 parser is strict by construction. It accepts CRLF line breaks only,
so a bare LF, an obs-fold, or whitespace in a field name is a `400`. It requires
exactly one `Host`. It refuses a declared body. It requires an exact three-field
request line. Together these close the request-smuggling surface.

Security headers go out on every response, errors included, and each is tunable
per site: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
`Permissions-Policy`, HSTS, and an optional CSP. The server refuses a request
whose `Host` disagrees with the connection's SNI, so one site's certificate
cannot front another site's content.

Wall-clock deadlines bound the handshake, the request head, and the connection
lifetime. The socket enforces them *below* rustls, which matters: a TLS read does
not return until a whole record arrives, so a deadline checked only between
requests never fires against a client that dribbles bytes inside one. A response
in flight must hold a minimum transfer rate. A "some byte moved" test would not
help, because one byte every few seconds satisfies it forever. A cap on
connections per source IP stops one peer taking every slot. The server re-reads
that cap and `max_response_secs` on reload, so neither needs a restart to change
while a flood runs.

### Operations

A watcher polls the config file, each document root, and each certificate every
2 seconds, then swaps in a new runtime once a change settles. Content,
certificates, sites, redirect rules, and even listen addresses all change without
a restart, and a request in flight always finishes against the snapshot it
started with. A config that fails to load leaves the running server on the
previous one.

## Performance

Reproduce all of it with [`bench/bench.sh`](https://github.com/nsinenko/bare-server/blob/main/bench/bench.sh). The script builds the
server, synthesises a fixed corpus, starts it, measures, and tears it down:

```sh
./bench/bench.sh            # everything
./bench/bench.sh --quick    # shorter load phases
./bench/bench.sh --no-load  # deterministic measurements only
```

### Compression

These depend only on the corpus and the build, so they reproduce on any machine:

| File | Identity | gzip | brotli | Saved (br) |
| --- | ---: | ---: | ---: | ---: |
| `index.html` | 9,217 B | 1,548 B | 1,314 B | 86% |
| `app.css` (40 KB) | 40,043 B | 5,826 B | 4,512 B | 89% |
| `app.js` (180 KB) | 180,024 B | 33,319 B | 25,874 B | 86% |
| `photo.png` | 200,000 B | n/a | n/a | skipped, already compressed |
| `tiny.txt` | 3 B | n/a | n/a | skipped, under `min_compress_bytes` |

### Build and footprint

| | |
| --- | --- |
| Static binary (aarch64 musl) | ~2.2 MB stripped (~1.2 MB compressed) |
| Docker image (`FROM scratch`) | ~2.4 MB, essentially just the binary |
| Boot to first served byte | ~1.0 to 1.8 s for 26 files / 809 KB, brotli q11 |
| Resident memory | 51 MiB for a 1.0 MB cache, `storage = memory` |

Exact binary size varies a little by target and toolchain. Release archives and
CI artifacts are compressed, so a download of roughly half that size is the same
binary, not a different build.

### Throughput

**Machine-specific.** One run on an Apple M3 Pro (12 cores, macOS 27) over
loopback, `wrk` with 4 threads and 64 connections for 10 s, while the load
generator competes for the same CPUs. Read it as a shape, not a score, and do
not compare it against numbers taken on a different host.

| Phase | Requests/s | p50 | p99 | Wire throughput |
| --- | ---: | ---: | ---: | ---: |
| 9 KB HTML, identity | 161,775 | 372 µs | 519 µs | 1.46 GB/s |
| 9 KB HTML, brotli | 166,212 | 369 µs | 496 µs | 284 MB/s |
| 180 KB JS, identity | 23,963 | 2.63 ms | 3.13 ms | 4.03 GB/s |
| 404 (not found) | 166,289 | 371 µs | 479 µs | 71 MB/s |
| `:80` to `:443` 301 | 166,061 | 375 µs | 517 µs | 58.6 MB/s |

The three small responses (the brotli page, the 404 and the 301) land within
0.2% of each other. The page and the 404 are each a single write of a buffer
that already exists. The 301 is a single write too, but of a buffer built per
request, because `Location` carries the request path. What the table shows
there is the ceiling of the machine rather than of any one code path. Brotli also beats identity on the same 9 KB page while moving a
fifth of the bytes: the variant is already compressed, so at request time the
only difference is how much goes on the wire. The identity page trails by 3%,
which is bandwidth rather than work: it moves 1.46 GB/s.

### Connection setup

The cost that dominates when clients do not reuse connections:

| | |
| --- | --- |
| Full TLS handshake | 2.44 ms median, 3.03 ms p90 (n=50, RSA-2048) |
| New connection per request | 14,655 req/s |
| Reused connection | 161,775 req/s |

That ~11x gap is the whole reason the server enables session resumption and 0-RTT
early data.

## What it does not do

No CGI, no reverse proxying, no directory listings, no HTTP/2 or HTTP/3, no
request log, no rate limits beyond the connection caps, no `Range` requests.
`GET` and `HEAD` only. If you need any of those, this is the wrong server, and
that is the point of the name.

## Design notes

**Why not pre-encrypt the files at boot too?** It is impossible, and it would not
help. TLS keys are negotiated per connection, and each record's nonce is bound to
its sequence number within that connection's stream. There is no key at boot.
Bytes encrypted for one client are useless to a second client, and that client
rejects them. That per-connection uniqueness is exactly what prevents replay. It
would also buy nothing: AEAD encryption of a small response with AES-NI costs a
fraction of a microsecond. The useful version of the idea is to precompute the
*plaintext* response and its *compressed* forms, which is what the server does.

**Why thread-per-connection?** The hot path is a lookup and a write, so a
connection thread spends nearly all of its life blocked in a syscall. A 128 KB
reserved stack and a semaphore that caps concurrency at 1024 keep the worst case
bounded. A panic in one connection stays inside its own thread instead of
aborting the process.

**Why is the release profile `opt-level = "s"`?** The request hot path is a
hashmap lookup, a header scan, and one `write_all`. The real CPU work happens
inside `ring`'s hand-written assembly, which `opt-level` does not touch. A build
optimized for size measured 12.8% smaller on static musl. Boot compression is the
one place where speed does buy something, so `brotli` and `miniz_oxide` are
pinned to `opt-level = 3` individually.

## License

MIT. See [LICENSE](LICENSE).
