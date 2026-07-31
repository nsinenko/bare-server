# Contributing

Thanks for taking an interest. This is a deliberately small project, so the most
useful contributions are usually bug reports with a reproducer, and focused
patches that keep the server small.

## Scope

bare server serves static files over HTTP/1.1 and TLS, and does nothing else.
The absence of CGI, reverse proxying, directory listings, HTTP/2, request
logging, and `Range` support is a design decision, not a backlog.

Before you write a patch that adds a feature, please open an issue that describes
the problem it solves. A change that adds a dependency, a background thread, or
allocation per request to the hot path needs a strong justification. Those are the
properties the whole design is built around.

Good contributions, in rough order of usefulness:

- Bug reports with a minimal reproducer (a config plus a `curl` invocation).
- Fixes for spec-conformance gaps in the HTTP/1.1 parser.
- Anything that lets a client consume more resources than the caps intend.
- Documentation fixes, especially in [`docs/`](docs/) and
  [`server.conf.example`](server.conf.example).
- Portability fixes for platforms other than Linux.

## Build and test

Requires Rust 1.85 or newer (`rust-version` in `Cargo.toml`, enforced by CI).

The crate is **Unix-only**: `read_token_file` uses `std::os::unix` for
`O_NOFOLLOW` and `st_nlink` without a `cfg` gate, so it does not build on
Windows. A patch that adds Windows support would have to solve that safely, not
just gate it away.

```sh
cargo build --locked
cargo test --locked
```

The integration tests in [`tests/integration.rs`](tests/integration.rs) start
real listeners on ephemeral ports and speak real TLS against them, so they
dominate the wall-clock time. The unit tests run in well under a second.

`openssl` and `curl` must be on `PATH`. The suite generates the certificates it
needs, so a clean checkout tests green with no setup: the RSA and EC fixtures land
in `target/test-certs/`, and each integration server gets a fresh self-signed
pair. Nothing reads a certificate from the source tree, and no key material is
committed.

```sh
cargo clippy --all-targets --locked -- -D warnings
```

**`cargo test --locked` must pass after every patch.** If you change behavior, the
patch should include the test that would have caught the old behavior.

There are no dev-dependencies, and a new one needs a good reason. The test suite
deliberately builds its own helpers (see [`src/testutil.rs`](src/testutil.rs))
rather than pulls in crates.

### Benchmarks

[`bench/bench.sh`](bench/bench.sh) builds the server, generates a fixed corpus,
runs it, and measures. The compression and footprint phases are deterministic
and reproduce anywhere; the throughput phases depend on the machine and need
`wrk` or `oha` installed.

```sh
./bench/bench.sh --quick
```

If a patch is meant to make something faster, include before and after output
from the same machine in the same sitting. Figures from different hosts are not
comparable.

One trap to know about before you write any client against this server: it selects
a site by **SNI**, so a client that connects to `127.0.0.1` sends no SNI and gets
its handshake refused with an `access_denied` alert. Use a hostname.

### Where tests live

- Unit tests sit in `#[cfg(test)] mod tests` at the bottom of the module they
  cover. A larger module splits them into several named modules
  (`signature_tests`, `policy_tests`, `disk_tests`) rather than one giant block.
- Integration tests live in `tests/integration.rs` and drive the real server over
  a real socket. Put a test here when it needs the whole stack, meaning TLS, the
  listeners and hot reload. Put it in a unit test otherwise.
- Test names are full sentences describing the behavior:
  `plain_http_redirects_to_https_with_force_ssl`, not `test_redirect_2`.

## Dependencies

The dependency list is short on purpose, and every entry earns its place:

- `rustls` and `ring`: TLS without OpenSSL, so the binary links as fully static
  musl.
- `rustls-pemfile`: it reads the certificate and the key.
- `flate2` (miniz_oxide backend) and `brotli`: pure-Rust compression, so the
  static build stays free of C dependencies.
- `libc`: declarations only, for the `O_NOFOLLOW` flag on the live ACME token
  read.

`Cargo.lock` is committed and builds use `--locked`. If a patch genuinely needs
a new dependency, say why in the pull request.

## Code style

The code is not `rustfmt`-normalized, and `cargo fmt` across the tree produces a
large unrelated diff. Please don't. Match the surrounding style instead: roughly
100 to 120 columns, and the existing alignment of trailing comments.

The one convention that matters more than formatting: **comments explain why,
not what.** This codebase is dense with reasoning about limits, timeouts, and
protocol corners, because the numbers are not self-evident and the next person
to touch them needs to know what they are trading off. For example:

```rust
// Below this a file is stored identity-only: the headers alone outweigh any
// saving, and a compressed form is often larger than the source.
pub(crate) const DEF_MIN_COMPRESS_BYTES: usize = 64;
```

If you change a constant, a timeout, or a limit, update the comment that
justifies it. If you add one, write that comment.

Other conventions:

- Everything internal is `pub(crate)`; nothing is exported.
- Prefer returning `Result<_, String>` with a message that names the offending
  config line over panicking. The parser is a pure `&str -> Result<Config, _>`
  precisely so it stays trivial to test.
- Avoid `unwrap()` outside tests. A poisoned lock is handled with
  `unwrap_or_else(PoisonError::into_inner)`, because a panicked connection thread
  must not take the server down with it.
- Panics stay contained per connection: the release profile deliberately keeps
  `panic = unwind`.

## Security-sensitive changes

Anything touching the request parser, the ACME token read, path resolution,
redirect target validation, or the connection caps is security-sensitive. Please
call that out in the pull request and describe what an attacker could attempt.

If you found a vulnerability, **do not open a public issue**. See
[SECURITY.md](SECURITY.md).

## Pull requests

- One logical change per pull request.
- Explain the *why* in the description; the diff already shows the what.
- Note any behavior change that an existing deployment would notice, especially
  a change to a default.
- Include the test that covers the change.

By contributing, you agree that your contributions are licensed under the MIT
License that covers the project.

## Releases

A version tag cuts a release. Nothing publishes on an ordinary push.

1. Move the `Unreleased` entries of [`CHANGELOG.md`](CHANGELOG.md) under a new
   version heading, with the release date and the compare links.
2. Bump `version` in `Cargo.toml`, and commit (`Cargo.lock` updates with it).
3. Tag and push:

   ```sh
   git tag -a v0.2.0 -m 'v0.2.0'
   git push origin v0.2.0
   ```

[`.github/workflows/release.yml`](.github/workflows/release.yml) then checks that
the tag matches `Cargo.toml`, and a mismatch fails before anything publishes. It
builds every supported target and publishes a GitHub Release with one `.tar.gz`
per target plus a `SHA256SUMS` file. Each archive carries the binary,
`README.md`, `LICENSE`, `server.conf.example`, and the systemd unit.

To rehearse without a release, run the workflow by hand from the Actions tab and
leave **dry run** checked. It builds and uploads the archives as workflow
artifacts, and publishes nothing.
