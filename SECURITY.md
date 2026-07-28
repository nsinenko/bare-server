# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**), which opens a channel visible only to
the maintainers.

Please include:

- What an attacker can achieve, and what access they need to start.
- A minimal reproducer — a config file plus the request that triggers it.
- The version or commit you tested against.

You should get an initial response within a week. Once a fix is ready it will be
released along with an advisory crediting you, unless you would rather stay
anonymous.

## Scope

This is a static file server, so the interesting boundary is everything a remote
client controls: the TLS handshake, the request head, and the request target.

**In scope:**

- Anything that reads or serves a file outside a configured document root.
- Request smuggling, response splitting, or header injection.
- Bypassing the connection caps, the header-size limit, or the wall-clock
  deadlines in a way that lets one client consume unbounded resources.
- Memory-safety failures, panics reachable from a remote request, or a panic
  that takes down more than the connection it happens on.
- Cache poisoning: making one client's request return another's response, or
  making a cached response outlive a content change unsafely.
- Serving the wrong site's content or certificate for a given `Host`/SNI.
- Anything that lets a request escape the `/.well-known/acme-challenge/` token
  confinement.

**Out of scope:**

- Misconfiguration by the operator — a document root containing files that were
  not meant to be public, a private key with world-readable permissions, or a
  `csp` value that permits too much. The [deployment
  guide](docs/DEPLOYMENT.md) covers the permissions that matter.
- The absence of features the server does not claim to have: no HTTP/2, no
  request logging, no rate limiting beyond the connection caps, no `Range`
  support.
- Denial of service that requires more bandwidth than the server has, rather
  than an asymmetry in the server's own handling.
- Findings against `gen-cert.sh`, which exists only to produce a self-signed
  certificate for local testing and says so.
- Vulnerabilities in dependencies that are already public and fixed upstream —
  open a normal issue or pull request to bump `Cargo.lock` instead.

## Design notes relevant to security

Some behavior looks alarming until you know why it is there:

- **TLS 1.3 0-RTT early data is enabled.** 0-RTT data is replayable by design.
  It is accepted here because the server only performs idempotent,
  side-effect-free `GET` and `HEAD` of public static files, so a replay can
  produce nothing an ordinary repeated request could not.
- **`/.well-known/acme-challenge/` is read from disk per request**, so that
  certificates can renew without a restart. Under `storage = memory` (the
  default) it is the *only* path that touches the filesystem — everything else
  is served from an in-memory table. Under `storage = disk` the body of every
  response is streamed from the boot-time snapshot as well; that path comes from
  a hash-table hit, never from the request, so it adds no traversal surface, but
  "no filesystem access per request" is a claim about memory mode only.

  The token is confined to a single `[A-Za-z0-9_-]` segment, so it can contain
  neither `/` nor `.`. The token file itself is opened with `O_NOFOLLOW` and
  `O_NONBLOCK` and then checked on the *handle* — regular file, one link, under
  the size cap — so a symlink, a hardlink to a file outside the root, and a FIFO
  are each refused without a check-then-use window. The two parent directories
  (`.well-known`, `acme-challenge`) are checked by path before the open, which is
  best-effort rather than atomic: swapping a parent for a symlink mid-request is
  a residual that still requires local write access to the document root.
- **A response must sustain a minimum transfer rate.** The wall-clock deadlines
  are enforced at the socket, *below* rustls, because `rustls::Stream::read` does
  not return until a whole TLS record has been assembled — so a client dribbling
  bytes inside one record never returns control to the request loop, and a
  deadline tested only between requests never fires. For the same reason the
  in-flight response is bounded by a *rate* (1 KiB per 30 s, about 34 B/s) rather
  than by "did any byte move": one byte every few seconds satisfies a liveness
  test forever while pinning a thread, an fd and both permits. A genuinely slow
  link is orders of magnitude above the floor; a deliberate stall is orders of
  magnitude below it.

- **`panic = unwind` is deliberate** in the release profile, so a panic in one
  connection thread stays contained to that thread rather than aborting the
  process. A panic that escapes that containment *is* a valid report.

- **`Host` must agree with SNI.** The certificate is chosen from SNI but the
  site — root, redirect rules, CSP, HSTS — is chosen from `Host`. A request whose
  `Host` names a different vhost than the handshake did is answered `404` rather
  than served one site's content under another's certificate and header policy.
  Nothing legitimate does this over HTTP/1.1, and this server speaks no HTTP/2,
  so there is no connection coalescing to accommodate.
- **HSTS is sent over plain HTTP too.** [RFC 6797
  §8.1](https://www.rfc-editor.org/rfc/rfc6797#section-8.1) makes user agents
  ignore it there, so it is inert rather than wrong.

## Supported versions

This is a small project without long-term release branches. Fixes land on the
default branch; please test against the latest commit before reporting.
