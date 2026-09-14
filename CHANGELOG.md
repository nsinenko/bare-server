# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
A `0.x` major carries no compatibility promise: a minor version can change
behaviour.

## [Unreleased]

## [0.2.1] - 2026-09-14

### Added

- The container image is published to Docker Hub
  (`nsinenko/bare-server`) as well as to `ghcr.io`, with the same tags
  (`x.y.z`, `x.y`, `latest`) and the same multi-arch manifest on both.

### Security

- `rustls` 0.23.43 -> 0.23.45 fixes RUSTSEC-2026-0285: the TLS 1.3
  handshake accepted messages across encryption-level boundaries. The
  server terminates TLS, so the fix applies to every HTTPS connection.

### Changed

- `rustls-webpki` 0.103.13 -> 0.103.15 and `flate2` 1.1.9 -> 1.1.10,
  routine updates pulled in by the lockfile bump.

## [0.2.0] - 2026-07-31

### Added

- Precomputed error responses. The server builds the six generated statuses
  (400, 404, 405, 408, 431, 500) at boot, in both connection forms, with the
  header and the body in one buffer. A request writes one slice. Under TLS
  every write is a separate record, so an error now costs one socket round
  trip instead of two. Each site holds its own set, built from its own header
  block, and the responses sent before a host resolves come from a
  server-level set, so every error carries the same headers as before.
- `Cache-Control: no-store` on every error response. A 404 without a
  `Cache-Control` header is heuristically cacheable, so a shared cache could
  keep answering 404 for a URL that the site publishes later.
- `Allow: GET, HEAD` on the 405 response, as RFC 9110 requires.

### Changed

- `max_total_bytes` now counts the error buffers, at boot and after a hot
  reload. One set is 5,690 bytes with the default headers, and the server holds
  one per site plus one for the responses that go out before a host resolves.

### Upgrade notes

- A config whose `max_total_bytes` cannot hold the error buffers now fails to
  start. The check runs before the content walk, so it also applies under
  `storage = disk` and to a redirect-only host, neither of which the walk
  covers. An operator who runs many hosts under a small budget must raise
  `max_total_bytes` to about `(sites + 1) x 6K` above the content total.

## [0.1.0] - 2026-07-28

### Added

- First public release. A static-file web server with built-in TLS
  termination, in a single static binary.

[Unreleased]: https://github.com/nsinenko/bare-server/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/nsinenko/bare-server/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nsinenko/bare-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nsinenko/bare-server/releases/tag/v0.1.0
