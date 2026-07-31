# Configuration reference

bare server takes one argument, the path to a config file, and almost nothing
else.

```sh
bare-server /etc/bare-server/server.conf
```

| Flag | Effect |
| --- | --- |
| `--quiet`, `-q` | Suppress the boot banner. Error and reload logging is unaffected. |
| `--version`, `-V` | Print `bare-server <version> (<target triple>)` and exit. |
| `--help`, `-h` | Print usage and exit. |

The boot banner prints only when stderr is a terminal, so it never reaches a
systemd journal or a container log and `--quiet` is rarely needed. See
[BRAND.md](../BRAND.md) for what it looks like.

[`server.conf.example`](../server.conf.example) is a working, fully annotated
starting point. This document is the complete reference.

## Format

The file is line-based. A bare `key = value` line at the top level is
server-wide. A `site <host[, host2, ...]> { ... }` block describes one virtual
host and may override most server-wide settings for itself.

```
listen = [::]:443
listen_http = [::]:80

brotli_quality = 5              # server-wide, and the default for every site
max_total_bytes = 2G            # server-only: one budget shared by all sites

site example.com, www.example.com {
    root = /var/www/example
    cert = /etc/bare-server/tls/example/cert.pem
    key  = /etc/bare-server/tls/example/key.pem

    force_ssl      = on             # default: :80 answers 301 to https://
    canonical_urls = on             # 301 the .html spellings onto /path/
    csp            = default-src 'self'
    cache_max_age  = 300

    redirect /old    -> /new
    redirect /docs/* -> /help/$1
}
```

A `#` starts a comment at the start of a line or after whitespace, so a value
containing `#` (a CSP hash, a URL fragment) does not need escaping.

Three rules worth knowing up front:

- **File order does not matter.** Each site is resolved against the finished
  top-level defaults, so a default written *below* a `site` block still applies
  to it.
- **A directive in the wrong place is an error, never a silent no-op.** Writing
  `max_total_bytes` inside a site block, or `root` outside one, fails the load
  with a message naming the line.
- **A rejected reload keeps the previous config serving.** Startup, by contrast,
  fails closed: a bad config at boot exits non-zero.

## Where each directive is allowed

| Scope | Directives |
| --- | --- |
| **Server only** | `listen`, `listen_http`, `storage`, `disk_cache`, `max_total_bytes`, `max_conns_per_ip`, `max_response_secs` |
| **Site only** | `root`, `cert`, `key`, `force_ssl`, `canonical_urls`, `redirect` |
| **Either** | `compression`, `brotli_quality`, `gzip_level`, `min_compress_bytes`, `max_brotli_bytes`, `max_gzip_bytes`, `max_file_size`, `cache_max_age`, `immutable_max_age`, `hsts_max_age`, `hsts_include_subdomains`, `hsts_preload`, `csp` |

For the "either" group, the server-level value is the default and a site block
overrides it for itself.

**Value formats.** Sizes take an optional binary `K`/`M`/`G` suffix (`1K` =
1024). Times are plain seconds. Booleans accept `on`/`off`, `true`/`false`,
`yes`/`no`, `1`/`0`.

## Server directives

### `listen` — required

The HTTPS listen address, as `host:port`. Split on the last colon, so IPv6
literals work.

```
listen = [::]:443
```

There is no default; omitting it fails the load.

### `listen_http`

The plain-HTTP listen address. **Omit it to run no HTTP listener at all** — note
that this also means port 80 stops issuing HTTPS redirects and ACME `http-01`
renewal will no longer work. (Writing `listen_http = :80` with an empty host is
rejected rather than quietly treated as "disabled".)

```
listen_http = [::]:80
```

### `storage`, `disk_cache`

```
storage = memory                        # default
storage = disk
disk_cache = /var/cache/bare-server     # required when storage = disk
```

`memory` loads every file into RAM at boot as a precomputed response — one write
per request, and resident memory scales with the site.

`disk` holds only a small index in RAM (path, mime, ETag, header) and snapshots
each body plus its gzip/brotli sidecars into `disk_cache`, streaming from there
at serve time. RAM stays roughly constant regardless of site size, at the cost of
per-request file I/O and roughly one copy of the site's size on disk. Each
rebuild writes a fresh snapshot directory; the previous one is removed once no
in-flight request still uses it, and any snapshot left behind by a previous run
is cleared at startup.

`disk_cache` must be a writable directory on real disk. Pointing it at a tmpfs
defeats the entire purpose — the path is never guessed for you, which is why it
is required rather than defaulted.

### `max_total_bytes`

```
max_total_bytes = 2G        # default
```

Refuse to cache past this, counted across every site and against the bytes
actually retained (identity, gzip, and brotli are each their own buffer). This
is server-only because it is one pool shared by all sites.

The precomputed error responses count too. They stay resident for the life of the
process, in both storage modes, and a redirect-only site holds a set as well. One
set is 5,690 bytes with the default headers, a little more with a CSP, and the
server holds one per site plus one for the responses that go out before any host
resolves. The floor is therefore about `(sites + 1) x 6K`, so only a budget in the
low kilobytes can fail on this alone. The load then stops before it reads that
site's document root, and the message names the bytes already retained rather than
send you looking at content that was never read.

Content that does not fit reports the URL it gave up on instead:
`cache exceeds max_total_bytes at <url>`.

A reload builds the replacement cache before it drops the old one, so **both are
resident at peak**. Size the host for twice this value.

### `max_conns_per_ip`

```
max_conns_per_ip = 64       # default; 0 = unlimited
```

Maximum concurrent connections from one source IP, applied per listener. A
single peer therefore cannot exhaust the global cap on its own. Browsers open
about 6 connections per host, so the default leaves ample room for real clients.

Set it to `0` when the server sits behind a shared-IP proxy or CDN, where every
connection appears to come from the same handful of addresses.

### `max_response_secs`

```
max_response_secs = 0       # default: off
```

An absolute wall-clock cap, in seconds, on a single in-flight response body.

This is **off by default on purpose**: it *will* truncate a legitimately slow
large download once the transfer outruns it. It is a knob for hosts that serve
only small files and want a hard ceiling on how long any one response may take.

It is not the primary defence against slow-read slot pinning, and does not need
to be. A response must sustain **1 KiB per 30 seconds** (about 34 B/s) or the
connection is dropped — a rate, not a "did any byte move" test, because one byte
every few seconds satisfies the latter forever. Any real client is orders of
magnitude above that floor.

Both this and [`max_conns_per_ip`](#max_conns_per_ip) are **re-read on reload**
and applied to live listeners, so they can be tightened while a flood is in
progress without restarting.

## Site directives

```
site <host[, host2, ...]> {
    root           = <dir>      # optional: omit for a redirect-only host
    cert           = <file>     # required
    key            = <file>     # required
    force_ssl      = on         # default
    canonical_urls = off        # default
    redirect <pattern> -> <target>
}
```

Several comma-separated names share one document root, one cache, one rule set,
and one certificate — which must cover every name listed via SANs, or the
(re)load is rejected.

> **Sites are selected by SNI.** There is no default or fallback site, so a
> client that connects to a bare IP address — which sends no SNI at all — has
> its handshake refused with an `access_denied` alert. This surprises people
> testing with `curl https://127.0.0.1:8443/`; use the hostname the site is
> configured under instead. Over plain HTTP the `Host` header plays the same
> role, and an unrecognised one gets a `404`.

### `root`

The document root. Optional: a block with no root is a redirect-only host (see
below). Serving requires the directory to exist and be readable at load time —
a missing root fails closed rather than silently serving 404s.

### `cert`, `key` — both required

PEM certificate chain and private key. Required **even for a redirect-only
host**: the TLS handshake has to complete before a `301` can be sent.

RSA and ECDSA keys both work. The pair is validated at load — a certificate that
does not match its key, or does not cover every host named in the block, is
rejected. The certificate files are watched, so renewal is picked up without a
restart.

### `force_ssl`

```
force_ssl = on      # default
```

On (the default), the plain-HTTP listener answers this host with a `301` to
`https://` instead of serving content over port 80. The redirect `Location`
names the HTTPS listener's actual port, so a non-standard port stays reachable.

Set it to `off` to serve the same content over plain HTTP as well.

Either way, `/.well-known/acme-challenge/` stays reachable over plain HTTP so
certificate renewal keeps working.

### `canonical_urls`

```
canonical_urls = off    # default
```

A site built from directory-index files answers the same document at `/about/`,
`/about/index.html`, and — if it predates clean URLs — `/about.html`. Turning
this on folds the latter two onto the first with a `301`:

| Request | 301 to |
| --- | --- |
| `/index.html` | `/` |
| `/foo/index.html` | `/foo/` |
| `/foo.html` | `/foo/` |
| `/myindex.html` | `/myindex/` (only a whole `index` segment counts) |

It runs *after* the explicit redirect rules, so a page that actually moved
reaches its new home in one hop rather than being folded onto its own old
directory first. The result never ends in `.html`, so it cannot match again —
one hop, no loop, for any input.

Off by default because it changes what a URL does.

### `redirect`

See [Redirect rules](#redirect-rules) below.

## Redirect rules

Every redirect this server emits is a `301 Moved Permanently`; there is no
status to configure. Rules are checked *before* the site's content, so a rule can
shadow a file that still exists.

Three pattern forms:

| Pattern | Matches | Capture |
| --- | --- | --- |
| `/old` | that exact path | — |
| `/docs/*` | `/docs/` and everything under it | `$1` = the remainder |
| `*` | anything not matched above | `$1` = the whole path |

```
redirect /old      -> /new
redirect /docs/*   -> /help/$1
redirect *         -> https://example.com$0
```

**Most specific wins regardless of the order written** — exact, then longest
matching prefix, then the catch-all. Matching is a hash lookup plus a scan
bounded by however many prefix rules you wrote; no pattern the format can
express makes it worse.

`*` is only valid as a trailing `/prefix/*`. A `*` mid-pattern, or one not on a
segment boundary (`/a*`), is rejected rather than given a surprising meaning.

**Targets.** A target is either a path starting with `/` — this host's scheme
and authority are filled in — or an absolute `http(s)://` URL, emitted verbatim.
Anything else (a bare `example.com`, a relative `new`) is rejected, because the
client would resolve it somewhere unintended.

**Substitutions.** `$0` is the whole request path, `$1` is what a `/prefix/*`
captured, and `$$` is a literal `$`. Any other `$` is left alone, so ordinary
URLs need no escaping. `$2` and up are rejected: there is exactly one capture.

The query string carries over unless the target already has one. Patterns match
the **raw, still-percent-encoded** request path, so write them exactly as a
client sends them.

**Rejected at load:** a duplicate pattern, more than one `*` rule per site, a
target containing control characters, and any rule that would redirect a path to
itself. Self-redirects are caught by *expanding* the target against a
representative match rather than by comparing spellings, so every way of writing
the same loop is refused — `/a -> /a`, `* -> $0`, `/docs/* -> /docs/$1`, and
equally `/a -> $0`, `/docs/* -> $0`, `/a -> $0#top`, `/a -> $0?v=1` (the fragment
is never sent on the next hop, and rules match with the query stripped, so both
of those come straight back). A target that is an absolute `http(s)://` URL is
exempt: it names another origin, and whether *that* loops is not knowable here.

### Redirect-only hosts

A host that only redirects is a site block with no `root`. It still needs a
certificate — the handshake must complete before the `301` can be sent.

```
site www.example.com {
    cert = /etc/bare-server/tls/example/cert.pem
    key  = /etc/bare-server/tls/example/key.pem
    redirect * -> https://example.com$0
}
```

Give such a host a `root` pointing at an ACME webroot if you want it to renew
its own certificate over `http-01`.

## Cache and compression

Compression runs once at boot, serially, **before the listeners bind** — these
are the knobs that trade startup time for bytes on the wire. On a small or
single-core box, lowering `brotli_quality` is by far the biggest win.

| Directive | Default | Meaning |
| --- | --- | --- |
| `compression` | `on` | Master switch; `off` serves identity only. |
| `brotli_quality` | `11` | 0–11. 11 runs at roughly 1 MB/s; 4–5 is far faster for about 5% more bytes. |
| `gzip_level` | `9` | 0–9. |
| `min_compress_bytes` | `64` | Below this a file is stored identity-only — headers outweigh any saving, and the compressed form is often larger. |
| `max_brotli_bytes` | `8M` | Above this a file gets no brotli variant. |
| `max_gzip_bytes` | `64M` | Above this a file is cached identity-only. |
| `max_file_size` | `256M` | Skip any single file larger than this entirely. |

The two ceilings differ by design. Brotli q11 is slow and nothing binds until it
finishes, so a 60 MB wasm bundle would turn every start into a multi-minute
connection-refused window; browsers handle a brotli-less response fine, but an
unreachable port they do not. gzip runs 20–50× faster, so it earns a much higher
ceiling.

A variant is kept only if it is actually smaller than the original, and
already-compressed types (images, video, fonts) are skipped outright.

### `Cache-Control` policy

| Directive | Default | Meaning |
| --- | --- | --- |
| `cache_max_age` | `0` | `max-age` for un-fingerprinted URLs. |
| `immutable_max_age` | `31536000` | `max-age` for fingerprinted URLs, sent with `immutable`. |

A **fingerprinted** URL is one whose filename ends in 8 or more hex digits, for
example `/style-0667c2b357.css`. Such a URL names one exact set of bytes, so it
is safe to pin for a year and mark immutable. (An all-decimal suffix does not
count, so `/report-20240101.pdf` is not mistaken for a fingerprint.)

Everything else revalidates by default, which the `ETag` makes cheap. Raising
`cache_max_age` above 0 pins un-hashed URLs too. Only do that if you can
tolerate stale content until it expires.

Neither directive applies to an error. Every 4xx and 5xx carries a fixed
`Cache-Control: no-store`, and that is not configurable. A 404 with no
`Cache-Control` is heuristically cacheable, so a shared cache could keep
answering 404 for a URL that the site published later.

## Security response headers

These go out on **every** response, including errors and redirects. All four
fixed headers are always sent:

```
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

Two more are configurable, and both are per-site overridable — a site with its
own CSP is the common case.

| Directive | Default | Meaning |
| --- | --- | --- |
| `hsts_max_age` | `63072000` | `Strict-Transport-Security` max-age (2 years). `0` omits the header. |
| `hsts_include_subdomains` | `on` | Append `; includeSubDomains`. |
| `hsts_preload` | `on` | Append `; preload`. |
| `csp` | *(empty)* | `Content-Security-Policy` value. Empty means no CSP header. |

HSTS is also sent over plain HTTP, where [RFC 6797 §8.1](https://www.rfc-editor.org/rfc/rfc6797#section-8.1)
makes a user agent ignore it — inert rather than wrong.

> **`hsts_preload` is a slow-to-reverse commitment.** Submitting a domain to the
> [preload list](https://hstspreload.org) hard-codes HTTPS-only into shipped
> browsers, and removal takes months to propagate. Leave it on only if you mean
> it.

Control characters are rejected in any header value, so a stray byte in a CSP
cannot inject into or truncate the header block.

## Validation and reload behavior

The config file, every document root, and every certificate are polled every 2
seconds. A change rebuilds the runtime and swaps it in atomically; in-flight
requests finish against the snapshot they started with.

- **At startup**, any error is fatal: the process prints a message naming the
  offending line and exits non-zero.
- **On reload**, an invalid config is logged and discarded — the previously
  loaded configuration keeps serving. The same applies to a certificate that
  fails to load or a listen address that fails to bind: the old listener keeps
  serving and the failure is logged.
- **Transient failures are retried** with exponential backoff up to 60 seconds,
  so a certificate written a moment after its key eventually converges without
  logging every 2 seconds forever.
- **An unreadable subdirectory fails the whole build.** Skipping it would install
  a cache that is silently missing a subtree — every asset under it 404s while
  the log reports success — so a deploy that lands one directory with the wrong
  ownership keeps the previous cache on reload, and refuses to boot on a fresh
  start, exactly as an unreadable root does.
- **Each site's tree is tracked separately**, not each root. Two `site` blocks may
  name the same `root` (to serve one tree under two certificates, or with
  different headers); each has its own cache and each is rebuilt.
- **A symlinked root is followed on every tick.** With the usual release layout
  (`/srv/www -> /srv/releases/42`) the server watches the resolved directory, so
  flipping the symlink to a new release is detected as a change and re-resolved,
  rather than leaving the server serving the old release indefinitely.

Everything in the file is re-read on reload. **Restarting is only needed to
change the binary.**
