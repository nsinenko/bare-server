# ---- Build stage: fully static musl binary via rustls + ring ---------------
# Tracks the `rust:alpine` tag: the crate versions are pinned by Cargo.lock, but
# the toolchain (rustc, musl, apk packages) follows upstream, so builds pick up
# toolchain fixes without a manual bump.
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
# Cargo.lock is copied and enforced: without it cargo re-resolves every
# dependency to the newest semver-compatible release at build time, so two
# builds of the same source can ship different code, including a compromised
# or regressed upstream, and including build scripts (ring, cc) that execute
# during the build. --locked makes a stale lockfile a build failure, not a
# silent upgrade.
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# +crt-static links libc statically so the binary needs no runtime libraries.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN cargo build --release --locked

# ---- Final stage: scratch (empty). The binary is fully static -------------
# No libc, no CA store (the server presents its own cert and never makes
# outbound TLS), no shell. Just the ~2.2 MB static binary, so the whole image is
# about 2.4 MB, since the binary is nearly all of it. USER is numeric since
# there is no /etc/passwd.
FROM scratch
COPY --from=builder /src/target/release/bare-server /server
EXPOSE 80 443
USER 1000:1000
# ENTRYPOINT/CMD split so the config path can be overridden at run time, e.g.
#   docker run ... bare-server /etc/bare-server/server.conf
ENTRYPOINT ["/server"]
CMD ["/etc/bare-server/server.conf"]
