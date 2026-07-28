//! Test-only helpers. Compiled only under `cfg(test)`.
//!
//! A minimal self-cleaning temp directory so the filesystem-touching tests
//! (cache building, tree signatures, the ACME read) can run against real files
//! without pulling in a dev-dependency, plus the TLS fixtures the `build_tls`
//! tests need.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(crate) fn new() -> TempDir {
        // Unique without randomness: pid distinguishes concurrent test binaries,
        // the counter distinguishes dirs within one binary's parallel threads.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("bare-server-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Write `data` to `rel` under the temp dir, creating parent dirs.
    pub(crate) fn write(&self, rel: &str, data: &[u8]) {
        let full = self.path.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(full, data).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ------------------------------------------------------------- TLS fixtures

/// Paths to the TLS material the `build_tls` tests need: an RSA cert/key pair
/// covering `localhost`, and an unrelated EC key used to check that a
/// mismatched pair is rejected.
pub(crate) struct TestCerts {
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
    /// An EC key that is *not* the counterpart of `cert`.
    pub(crate) other_key: PathBuf,
}

/// Generate the fixtures once per machine, under `target/`.
///
/// Generating them keeps the suite self-contained on a clean checkout without
/// committing key material or adding a dev-dependency. They live under
/// `target/` so they survive between runs but are never mistaken for something
/// deployable, and are produced via a temp-dir-then-rename so two concurrently
/// running test binaries cannot observe a half-written PEM.
pub(crate) fn test_certs() -> TestCerts {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/test-certs");
    let certs = TestCerts {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
        other_key: dir.join("ec-key.pem"),
    };
    if certs.cert.exists() && certs.key.exists() && certs.other_key.exists() {
        return certs;
    }

    let staging = TempDir::new();
    let (c, k, o) = (
        staging.path().join("cert.pem"),
        staging.path().join("key.pem"),
        staging.path().join("ec-key.pem"),
    );
    run_openssl(&[
        "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", k.to_str().unwrap(),
        "-out", c.to_str().unwrap(),
        // A long life: these are regenerated only when target/ is cleaned, and
        // an expired fixture would fail the suite for a reason unrelated to it.
        "-days", "3650", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost",
    ]);
    run_openssl(&[
        "ecparam", "-genkey", "-name", "prime256v1",
        "-out", o.to_str().unwrap(),
    ]);

    std::fs::create_dir_all(&dir).unwrap();
    // Rename each into place; losing the race to another test binary is fine,
    // since both produce an equally valid fixture.
    for (from, to) in [(&c, &certs.cert), (&k, &certs.key), (&o, &certs.other_key)] {
        let _ = std::fs::rename(from, to);
    }
    assert!(
        certs.cert.exists() && certs.key.exists() && certs.other_key.exists(),
        "failed to stage TLS test fixtures in {}",
        dir.display()
    );
    certs
}

fn run_openssl(args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .output()
        .expect("run openssl (required to generate TLS test fixtures)");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}
