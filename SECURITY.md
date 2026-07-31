# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**

Use GitHub's private vulnerability reporting on this repository: the **Security**
tab, then **Report a vulnerability**. That opens a channel visible only to the
maintainers.

Please include:

- What an attacker can achieve, and what access they need to start.
- A minimal reproducer: a config file plus the request that triggers it.
- The version or commit you tested against.

You should get a first response within a week. Once a fix is ready it goes out
with an advisory that credits you, unless you would rather stay anonymous.

## Scope

This is a static file server, so the interesting boundary is everything a remote
client controls: the TLS handshake, the request head, and the request target.

**In scope:**

- Anything that reads or serves a file outside a configured document root.
- Request smuggling, response splitting, or header injection.
- Any bypass of the connection caps, the header-size limit, or the wall-clock
  deadlines that lets one client consume unbounded resources.
- Memory-safety failures, panics reachable from a remote request, or a panic
  that takes down more than the connection it happens on.
- Cache poisoning: one client's request returns another client's response, or a
  cached response outlives a content change unsafely.
- Serving the wrong site's content or certificate for a given `Host`/SNI.
- Anything that lets a request escape the `/.well-known/acme-challenge/` token
  confinement.

**Out of scope:**

- Misconfiguration by the operator: a document root that holds files nobody
  meant to publish, a private key with world-readable permissions, or a `csp`
  value that permits too much. The [deployment
  guide](docs/DEPLOYMENT.md) covers the permissions that matter.
- The absence of features the server does not claim to have: no HTTP/2, no
  request log, no rate limits beyond the connection caps, no `Range` support.
- Denial of service that needs more bandwidth than the server has, rather than an
  asymmetry in how the server itself works.
- Findings against `gen-cert.sh`, which exists only to produce a self-signed
  certificate for a local test, and says so.
- Vulnerabilities in dependencies that are already public and fixed upstream.
  Open a normal issue or pull request to bump `Cargo.lock` instead.

## Design notes relevant to security

Some behavior looks alarming until you know why it is there:

- TLS 1.3 0-RTT early data is enabled, and 0-RTT data is replayable by design.
  The server accepts it because it only answers `GET` and `HEAD` for public static
  files, which are idempotent and have no side effects, so a replay can produce
  nothing an ordinary repeated request could not.
- The server reads `/.well-known/acme-challenge/` from disk per request, so that
  certificates can renew without a restart. Under `storage = memory` (the
  default) it is the *only* path that touches the filesystem, and everything else
  comes from an in-memory table. Under `storage = disk` the body of every response
  streams from the boot-time snapshot as well. That path comes from a hash-table
  hit, never from the request, so it adds no traversal surface, but "no filesystem
  access per request" is a claim about memory mode only.

  The server confines the token to a single `[A-Za-z0-9_-]` segment, so it can
  contain neither `/` nor `.`. It opens the token file with `O_NOFOLLOW` and
  `O_NONBLOCK`, then checks the *handle* rather than the path: regular file, one
  link, under the size cap. A symlink, a hardlink to a file outside the root, and
  a FIFO are each refused with no check-then-use window. The server checks the two
  parent directories (`.well-known`, `acme-challenge`) by path before the open,
  which is best-effort rather than atomic. A parent swapped for a symlink
  mid-request is a residual that still needs local write access to the document
  root.
- A response must hold a minimum transfer rate, and the socket enforces every
  wall-clock deadline *below* rustls. That placement matters, because
  `rustls::Stream::read` does not return until a whole TLS record arrives. A client
  that dribbles bytes inside one record therefore never returns control to the
  request loop, and a deadline tested only between requests never fires. For the
  same reason a *rate* bounds the response in flight (1 KiB per 30 s, about
  34 B/s) rather than a "did any
  byte move" test, which one byte every few seconds satisfies forever while it
  pins a thread, an fd and both permits. A genuinely slow link is orders of
  magnitude above the floor, and a deliberate stall is orders of magnitude below
  it.
- `panic = unwind` is deliberate in the release profile. A panic in one connection
  thread therefore stays inside that thread and does not abort the process. A panic
  that escapes that containment *is* a valid report.
- `Host` must agree with SNI. SNI chooses the certificate, but `Host` chooses the
  site, meaning its root, redirect rules, CSP and HSTS. A request whose `Host`
  names a different vhost than the handshake did is answered `404`, rather than
  served one site's content under another site's certificate and header policy.
  Nothing legitimate does this over HTTP/1.1, and this server speaks no HTTP/2, so
  there is no connection coalescing to accommodate.
- The server sends HSTS over plain HTTP too. [RFC 6797
  §8.1](https://www.rfc-editor.org/rfc/rfc6797#section-8.1) makes a user agent
  ignore it there, so it is inert rather than wrong.

## Supported versions

This is a small project without long-term release branches. Fixes land on the
default branch, so please test against the latest commit first.
