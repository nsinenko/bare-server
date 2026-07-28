//! End-to-end integration tests.
//!
//! These boot the real `bare-server` binary as a subprocess against a temp
//! document root, a freshly generated self-signed certificate, and OS-assigned
//! ports, then drive it with real clients. This covers the ground the unit
//! tests deliberately cannot reach: the accept loop, the TLS handshake, the
//! plain-HTTP listener, and the `watch()` hot-reload loop — all over real
//! sockets.
//!
//! The TLS client is `curl` (present on essentially every dev/CI box). It runs
//! with `-k`: the point is to exercise the server's TLS stack, not curl's chain
//! verification, and the self-signed test cert would otherwise need per-backend
//! trust wiring. SNI is forced to `localhost` (the name the test cert covers)
//! via `--resolve`. The plain-HTTP path needs no TLS, so it uses a raw TcpStream
//! and stays dependency-free.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bare-server");

/// Grab a currently-free localhost port by binding :0 and reading it back.
/// Classic get-a-free-port: a small race window remains, fine for tests.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn unique_dir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("bare-server-it-{}-{tag}-{n}", std::process::id()));
    p
}

fn tool_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn curl_available() -> bool {
    // curl uses `--version`; `version` is rejected, but a non-zero exit still
    // proves the binary runs, which is all we need.
    Command::new("curl").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok()
}

fn openssl_available() -> bool {
    tool_available("openssl")
}

/// Generate a fresh self-signed cert+key for `localhost` (mirrors gen-cert.sh),
/// so a cert-reload test can swap in a certificate distinct from the boot one.
fn gen_localhost_cert(cert: &Path, key: &Path) {
    let status = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key.to_str().unwrap(),
            "-out", cert.to_str().unwrap(),
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run openssl");
    assert!(status.success(), "openssl cert generation failed");
}

/// A running server subprocess plus its temp document root. Killed and cleaned
/// up on drop.
struct TestServer {
    child: Child,
    https: u16,
    http: u16,
    root: PathBuf,
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    cfg_path: PathBuf,
    force_ssl: bool,
    extra: String,
    site_extra: String,
}

impl TestServer {
    /// Default fixture forces SSL on the site, so the plain-HTTP listener
    /// redirects — the posture most deployments want.
    fn start() -> TestServer {
        TestServer::start_with(true)
    }

    fn start_with(force_ssl: bool) -> TestServer {
        TestServer::start_tuned(force_ssl, "")
    }

    /// As `start_with`, plus extra server-level config lines (the tuning knobs).
    fn start_tuned(force_ssl: bool, extra: &str) -> TestServer {
        TestServer::start_full(force_ssl, extra, "")
    }

    /// As `start_tuned`, plus extra lines *inside* the site block — the per-site
    /// overrides and `redirect` rules.
    fn start_site(site_extra: &str) -> TestServer {
        TestServer::start_full(true, "", site_extra)
    }

    fn start_full(force_ssl: bool, extra: &str, site_extra: &str) -> TestServer {
        let extra = extra.to_string();
        let site_extra = site_extra.to_string();
        let dir = unique_dir("srv");
        let root = dir.join("www");
        std::fs::create_dir_all(&root).unwrap();
        // Seed content.
        write(&root, "index.html", b"<h1>home</h1>");
        write(&root, "about.html", b"<h1>about</h1>");
        write(&root, "blog/index.html", b"<h1>blog</h1>");
        write(&root, "style.css", &"body { color: red; }\n".repeat(20).into_bytes());
        write(&root, ".well-known/acme-challenge/tok-abc", b"KEYAUTHZ");

        // Generate this server's cert into its own temp dir, so a cert-reload
        // test can overwrite the running server's PEMs freely, and so a clean
        // checkout needs no setup.
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        gen_localhost_cert(&cert, &key);

        let (https, http) = {
            let a = free_port();
            let mut b = free_port();
            while b == a {
                b = free_port();
            }
            (a, b)
        };

        let cfg = render_config(
            https,
            http,
            &extra,
            &root,
            &cert,
            &key,
            force_ssl,
            &site_extra,
        );
        let cfg_path = dir.join("server.conf");
        std::fs::write(&cfg_path, cfg).unwrap();

        let child = Command::new(BIN)
            .arg(&cfg_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bare-server");

        let mut srv =
            TestServer { child, https, http, root, dir, cert, key, cfg_path, force_ssl, extra, site_extra };
        srv.wait_ready();
        srv
    }

    /// SHA-256 fingerprint of the certificate the server currently presents on
    /// the HTTPS listener (via `openssl s_client`). `None` if the handshake or
    /// openssl fails. Used to observe a cert hot-reload from the outside.
    fn served_fingerprint(&self) -> Option<String> {
        let pipeline = format!(
            "openssl s_client -connect 127.0.0.1:{} -servername localhost </dev/null 2>/dev/null \
             | openssl x509 -noout -fingerprint -sha256",
            self.https
        );
        let out = Command::new("sh").arg("-c").arg(&pipeline).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let fp = text.split('=').nth(1)?.trim().to_string();
        (!fp.is_empty()).then_some(fp)
    }

    /// Poll `served_fingerprint` until it returns (the server is freshly up).
    fn fingerprint(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(fp) = self.served_fingerprint() {
                return fp;
            }
            assert!(Instant::now() < deadline, "could not read served certificate");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Poll until the served certificate differs from `old`, or time out.
    fn wait_cert_changes_from(&self, old: &str, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if self.served_fingerprint().as_deref().is_some_and(|fp| fp != old) {
                return;
            }
            assert!(Instant::now() < deadline, "served certificate did not change from {old}");
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("server exited early with {status} (port in use? cert unreadable?)");
            }
            let up = TcpStream::connect(("127.0.0.1", self.https)).is_ok()
                && TcpStream::connect(("127.0.0.1", self.http)).is_ok();
            if up {
                return;
            }
            if Instant::now() > deadline {
                panic!("server did not become ready within 20s");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Run curl against the HTTPS listener with SNI/Host = localhost. `flags`
    /// are extra curl args (e.g. `-i`, `-I`, `-H ...`). Returns stdout.
    fn curl(&self, flags: &[&str], path: &str) -> String {
        let url = format!("https://localhost:{}{path}", self.https);
        let resolve = format!("localhost:{}:127.0.0.1", self.https);
        let mut args = vec!["-sS", "-k", "--resolve", &resolve];
        args.extend_from_slice(flags);
        args.push(&url);
        let out = Command::new("curl").args(&args).output().expect("run curl");
        assert!(
            out.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// One raw plain-HTTP request against this server's HTTP listener.
    fn plain(&self, raw_request: &str) -> String {
        plain_request(self.http, raw_request).expect("plain-HTTP connect")
    }

    /// Rewrite server.conf to move the plain-HTTP listener to `new_http`,
    /// leaving the HTTPS listener, site, and certs unchanged. The watcher should
    /// pick this up and rebind the HTTP listener without a restart.
    fn set_http_port(&self, new_http: u16) {
        let cfg = render_config(
            self.https,
            new_http,
            &self.extra,
            &self.root,
            &self.cert,
            &self.key,
            self.force_ssl,
            &self.site_extra,
        );
        std::fs::write(&self.cfg_path, cfg).unwrap();
    }
}

/// The block-format config every fixture runs against.
#[allow(clippy::too_many_arguments)]
fn render_config(
    https: u16,
    http: u16,
    extra: &str,
    root: &Path,
    cert: &Path,
    key: &Path,
    force_ssl: bool,
    site_extra: &str,
) -> String {
    // force_ssl is the default, so the opt-out must be explicit when a test
    // wants content served over plain HTTP.
    let flag = if force_ssl { "" } else { "    force_ssl = off\n" };
    let site_extra = if site_extra.is_empty() {
        String::new()
    } else {
        format!("{site_extra}\n")
    };
    format!(
        "listen = 127.0.0.1:{https}\n\
         listen_http = 127.0.0.1:{http}\n\
         {extra}\
         site localhost {{\n\
         \x20   root = {root}\n\
         \x20   cert = {cert}\n\
         \x20   key  = {key}\n\
         {flag}{site_extra}}}\n",
        root = root.display(),
        cert = cert.display(),
        key = key.display(),
    )
}

/// One raw plain-HTTP request over a fresh TCP connection (Connection: close so
/// the read terminates at EOF). `None` if the port refuses the connection —
/// used to observe a listener being retired.
fn plain_request(port: u16, raw_request: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(raw_request.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write(root: &std::path::Path, rel: &str, data: &[u8]) {
    let full = root.join(rel);
    if let Some(p) = full.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(full, data).unwrap();
}

/// Case-insensitive header lookup in a curl `-i` response.
fn header(resp: &str, name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    resp.split("\r\n").find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k.trim().to_ascii_lowercase() == name).then(|| v.trim().to_string())
    })
}

fn status_ok(resp: &str, code: &str) -> bool {
    resp.lines().next().map(|l| l.contains(code)).unwrap_or(false)
}

// ---------------------------------------------------------------- HTTPS path

#[test]
fn https_serves_index_over_real_tls() {
    if !curl_available() {
        eprintln!("skipping: curl not found");
        return;
    }
    let srv = TestServer::start();
    let r = srv.curl(&["-i"], "/");
    assert!(status_ok(&r, "200"), "{r}");
    assert_eq!(header(&r, "content-type").as_deref(), Some("text/html; charset=utf-8"));
    assert!(r.contains("<h1>home</h1>"));
    // HTTP/1.1 default keep-alive is reflected back.
    assert_eq!(header(&r, "connection").as_deref(), Some("keep-alive"));
    // A baked security header made it through the whole stack.
    assert!(header(&r, "strict-transport-security").is_some());
}

#[test]
fn https_head_has_no_body() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    let r = srv.curl(&["-I"], "/");
    assert!(status_ok(&r, "200"), "{r}");
    assert_eq!(header(&r, "content-length").as_deref(), Some("13"));
    // curl -I is HEAD; nothing after the header block.
    assert_eq!(r.split("\r\n\r\n").nth(1).unwrap_or("").trim(), "");
}

#[test]
fn https_missing_is_404_and_bad_host_is_404() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    assert!(status_ok(&srv.curl(&["-i"], "/nope"), "404"));
    // Force an unconfigured Host: the allowlist answers 404.
    let r = srv.curl(&["-i", "-H", "Host: evil.example"], "/");
    assert!(status_ok(&r, "404"), "{r}");
}

#[test]
fn https_clean_url_and_dir_index_redirect() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    // Extensionless clean URL resolves to about.html.
    assert!(status_ok(&srv.curl(&["-i"], "/about"), "200"));
    // A directory without a trailing slash 301s to the slash form.
    let r = srv.curl(&["-i"], "/blog");
    assert!(status_ok(&r, "301"), "{r}");
    // The redirect names the HTTPS listener's real port (finding 3): on a
    // standard :443 deployment the port is omitted, but the test uses an
    // OS-assigned port, so it must appear or the Location would be unreachable.
    assert_eq!(
        header(&r, "location").as_deref(),
        Some(format!("https://localhost:{}/blog/", srv.https).as_str())
    );
}

#[test]
fn https_content_negotiation_and_conditional_get() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    // Explicit Accept-Encoding: br -> the server sends the brotli variant.
    let br = srv.curl(&["-i", "-H", "Accept-Encoding: br"], "/style.css");
    assert_eq!(header(&br, "content-encoding").as_deref(), Some("br"));
    assert_eq!(header(&br, "vary").as_deref(), Some("Accept-Encoding"));

    // Grab the identity ETag, then revalidate -> 304.
    let first = srv.curl(&["-i"], "/style.css");
    let etag = header(&first, "etag").expect("etag present");
    let inm = format!("If-None-Match: {etag}");
    let second = srv.curl(&["-i", "-H", &inm], "/style.css");
    assert!(status_ok(&second, "304"), "{second}");
}

// ---------------------------------------------------------- plain-HTTP path

#[test]
fn plain_http_redirects_to_https_with_force_ssl() {
    // Default fixture sets `force_ssl` on the site.
    let srv = TestServer::start();
    let r = srv.plain("GET /page?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(status_ok(&r, "301"), "{r}");
    // Location targets the HTTPS listener's real (OS-assigned) port — see the
    // dir-index test above for why the port is present here but not on :443.
    assert_eq!(
        header(&r, "location").as_deref(),
        Some(format!("https://localhost:{}/page?x=1", srv.https).as_str())
    );
}

#[test]
fn plain_http_serves_acme_challenge_without_redirect() {
    let srv = TestServer::start();
    let r = srv.plain(
        "GET /.well-known/acme-challenge/tok-abc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(status_ok(&r, "200"), "ACME must be answered on :80, not redirected: {r}");
    assert_eq!(header(&r, "cache-control").as_deref(), Some("no-store"));
    assert!(r.ends_with("KEYAUTHZ"));

    // A non-existent token is a 404, still not a redirect.
    let miss = srv.plain(
        "GET /.well-known/acme-challenge/absent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(status_ok(&miss, "404"), "{miss}");
}

#[test]
fn plain_http_rejects_a_declared_body() {
    let srv = TestServer::start();
    // Content-Length > 0 with no method that takes a body: 400 + close, so the
    // undrained body can never be re-parsed as the next request (CL.0 desync).
    let r = srv.plain(
        "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO",
    );
    assert!(status_ok(&r, "400"), "{r}");
}

// ------------------------------------------------------------- hot reload

#[test]
fn hot_reload_follows_a_release_symlink_flip() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    assert!(srv.curl(&["-i"], "/").contains("<h1>home</h1>"));

    // Turn the configured root into a symlink pointing at a new release, the
    // shape every atomic-deploy tool uses. The server canonicalises the root at
    // boot and watches the *resolved* directory, so without re-resolving the
    // configured path each tick nothing under the watched directory ever changes
    // and the new release stays invisible for the life of the process.
    let release = srv.dir.join("release-2");
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join("index.html"), b"<h1>release-2</h1>").unwrap();
    std::fs::remove_dir_all(&srv.root).unwrap();
    std::os::unix::fs::symlink(&release, &srv.root).unwrap();

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if srv.curl(&["-i"], "/").contains("<h1>release-2</h1>") {
            break;
        }
        if Instant::now() > deadline {
            panic!("a symlink flip to a new release was not picked up within 20s");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn hot_reload_picks_up_edited_content() {
    if !curl_available() {
        return;
    }
    let srv = TestServer::start();
    assert!(srv.curl(&["-i"], "/").contains("<h1>home</h1>"));

    // Overwrite the index; the watcher polls every 2s and debounces one tick, so
    // the change should go live within a few seconds without a restart.
    write(&srv.root, "index.html", b"<h1>reloaded</h1>");

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if srv.curl(&["-i"], "/").contains("<h1>reloaded</h1>") {
            break; // watcher rebuilt and swapped the cache
        }
        if Instant::now() > deadline {
            panic!("hot reload did not pick up the edit within 15s");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

// ------------------------------------------------------- certificate reload

#[test]
fn cert_hot_reload_swaps_the_served_certificate() {
    if !curl_available() || !openssl_available() {
        eprintln!("skipping: curl/openssl not found");
        return;
    }
    let srv = TestServer::start();
    let boot_fp = srv.fingerprint();

    // Drop a different (but still localhost-covering) certificate over the
    // running PEMs — the shape of an ACME/certbot renewal.
    let new_cert = srv.dir.join("renewed-cert.pem");
    let new_key = srv.dir.join("renewed-key.pem");
    gen_localhost_cert(&new_cert, &new_key);
    // Key first, then cert: the watcher debounces one 2s tick, so it never sees
    // a half-updated pair regardless of order — but this mirrors atomic deploys.
    std::fs::copy(&new_key, &srv.key).unwrap();
    std::fs::copy(&new_cert, &srv.cert).unwrap();

    // The watcher should rebuild TLS only and present the new cert within a few
    // ticks — no restart, no content rebuild.
    srv.wait_cert_changes_from(&boot_fp, Duration::from_secs(20));

    // And the site is still served over the new certificate.
    assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
    assert!(srv.curl(&["-i"], "/").contains("<h1>home</h1>"));
}

#[test]
fn a_bad_certificate_is_ignored_then_recovered_from() {
    if !curl_available() || !openssl_available() {
        eprintln!("skipping: curl/openssl not found");
        return;
    }
    let srv = TestServer::start();
    let boot_fp = srv.fingerprint();

    // A half-written / corrupt PEM must NOT be swapped in: build_tls fails to
    // parse it, and the watcher keeps the previous certificate.
    std::fs::write(&srv.cert, b"garbage, not a certificate\n").unwrap();
    std::thread::sleep(Duration::from_secs(6)); // several watcher ticks
    assert_eq!(
        srv.served_fingerprint().as_deref(),
        Some(boot_fp.as_str()),
        "a bad certificate must not replace the working one"
    );
    assert!(status_ok(&srv.curl(&["-i"], "/"), "200"), "server keeps serving on a bad cert");

    // Restoring a valid certificate recovers: a new signature clears the backoff
    // and the reload goes through.
    let good_cert = srv.dir.join("recover-cert.pem");
    let good_key = srv.dir.join("recover-key.pem");
    gen_localhost_cert(&good_cert, &good_key);
    std::fs::copy(&good_key, &srv.key).unwrap();
    std::fs::copy(&good_cert, &srv.cert).unwrap();
    srv.wait_cert_changes_from(&boot_fp, Duration::from_secs(20));
    assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
}

// ---------------------------------------------------- listener rebind on reload

#[test]
fn config_reload_moves_the_http_listener() {
    let srv = TestServer::start();
    let old = srv.http;
    let req = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    // The original HTTP port issues redirects.
    assert!(status_ok(&plain_request(old, req).expect("old port up"), "301"));

    // Move listen_http to a new free port and let the watcher reconcile it.
    let mut new_http = free_port();
    while new_http == srv.https || new_http == old {
        new_http = free_port();
    }
    srv.set_http_port(new_http);

    // The new port comes up serving redirects (rebind: bind-new-before-retire).
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if plain_request(new_http, req).is_some_and(|r| status_ok(&r, "301")) {
            break;
        }
        assert!(Instant::now() < deadline, "new HTTP port never started serving");
        std::thread::sleep(Duration::from_millis(300));
    }

    // ...and the old port stops accepting once the old accept loop is retired.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if plain_request(old, req).is_none() {
            break;
        }
        assert!(Instant::now() < deadline, "old HTTP port kept accepting after rebind");
        std::thread::sleep(Duration::from_millis(300));
    }

    // HTTPS is untouched by an HTTP-only address change.
    if curl_available() {
        assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
    }
}

#[test]
fn plain_http_serves_content_without_force_ssl() {
    // Same server, site declared WITHOUT `force_ssl`: :80 serves the content
    // instead of upgrading. This is the opt-out half of the flag.
    let srv = TestServer::start_with(false);
    let r = srv
        .plain("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(status_ok(&r, "200"), "expected content over plain HTTP: {r}");
    assert!(r.contains("<h1>home</h1>"), "body should be served over :80: {r}");

    // HTTPS is unaffected and still serves the same site.
    if curl_available() {
        assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
    }
}

#[test]
fn server_tuning_applies_and_survives_a_hot_reload() {
    if !curl_available() {
        eprintln!("skipping: curl not found");
        return;
    }
    // compression disabled at the server level.
    let srv = TestServer::start_tuned(true, "compression = off\ncache_max_age = 99\n");
    let r = srv.curl(&["-i", "-H", "Accept-Encoding: br"], "/style.css");
    assert!(status_ok(&r, "200"), "{r}");
    assert!(header(&r, "content-encoding").is_none(), "compression=off should disable br: {r}");
    assert_eq!(header(&r, "cache-control").as_deref(), Some("public, max-age=99, must-revalidate"));

    // Edit content so the watcher rebuilds this root, then confirm the rebuild
    // used the runtime's policy rather than reverting to the defaults.
    write(&srv.root, "index.html", b"<h1>reloaded-tuned</h1>");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if srv.curl(&["-i"], "/").contains("reloaded-tuned") {
            break;
        }
        assert!(Instant::now() < deadline, "hot reload did not land");
        std::thread::sleep(Duration::from_millis(300));
    }
    let after = srv.curl(&["-i", "-H", "Accept-Encoding: br"], "/style.css");
    assert!(
        header(&after, "content-encoding").is_none(),
        "a hot reload must rebuild with the configured tuning, not the defaults: {after}"
    );
    assert_eq!(header(&after, "cache-control").as_deref(), Some("public, max-age=99, must-revalidate"));
}

// -------------------------------------------------- per-site redirect rules

#[test]
fn configured_redirect_rules_are_served_as_301s() {
    let srv = TestServer::start_site(
        "    redirect /old      -> /new\n\
         \x20   redirect /docs/*   -> /help/$1\n\
         \x20   redirect /gone     -> https://other.test/x",
    );

    // Exact rule: a bare-path target gets this host's scheme and authority.
    let r = srv.curl(&["-i"], "/old");
    assert!(status_ok(&r, "301"), "{r}");
    assert_eq!(
        header(&r, "location").as_deref(),
        Some(format!("https://localhost:{}/new", srv.https).as_str())
    );

    // Prefix rule: the remainder rides along as $1.
    let r = srv.curl(&["-i"], "/docs/a/b");
    assert_eq!(
        header(&r, "location").as_deref(),
        Some(format!("https://localhost:{}/help/a/b", srv.https).as_str())
    );

    // Absolute target: emitted verbatim, no authority rewriting.
    let r = srv.curl(&["-i"], "/gone");
    assert!(status_ok(&r, "301"), "{r}");
    assert_eq!(header(&r, "location").as_deref(), Some("https://other.test/x"));

    // The query string survives.
    let r = srv.curl(&["-i"], "/old?a=1&b=2");
    assert_eq!(
        header(&r, "location").as_deref(),
        Some(format!("https://localhost:{}/new?a=1&b=2", srv.https).as_str())
    );

    // Unmatched paths still serve content.
    assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
}

#[test]
fn a_redirect_rule_reaches_the_plain_listener_in_one_hop() {
    // A force_ssl site: the rule runs before the HTTP -> HTTPS upgrade, so the
    // client is sent straight to the final https:// target.
    let srv = TestServer::start_site("    redirect /old -> https://other.test/x");
    let r = srv.plain("GET /old HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert!(status_ok(&r, "301"), "{r}");
    assert_eq!(header(&r, "location").as_deref(), Some("https://other.test/x"));
}

#[test]
fn a_catch_all_rule_still_leaves_the_acme_challenge_answerable() {
    // Renewal must keep working on a host that redirects everything.
    let srv = TestServer::start_site("    redirect * -> https://other.test$0");
    let r = srv.plain(
        "GET /.well-known/acme-challenge/tok-abc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(status_ok(&r, "200"), "ACME must survive a catch-all rule: {r}");
    assert!(r.ends_with("KEYAUTHZ"));
    // Everything else is redirected, over TLS as well as plain HTTP.
    let r = srv.curl(&["-i"], "/anything");
    assert_eq!(header(&r, "location").as_deref(), Some("https://other.test/anything"));
}

#[test]
fn per_site_settings_reach_the_served_response() {
    // A site block overriding the header and cache-control policy for itself.
    let srv = TestServer::start_site(
        "    csp = default-src 'self'\n\
         \x20   cache_max_age = 123\n\
         \x20   hsts_max_age = 0",
    );
    let r = srv.curl(&["-i"], "/");
    assert!(status_ok(&r, "200"), "{r}");
    assert_eq!(header(&r, "content-security-policy").as_deref(), Some("default-src 'self'"));
    assert_eq!(header(&r, "cache-control").as_deref(), Some("public, max-age=123, must-revalidate"));
    assert!(
        header(&r, "strict-transport-security").is_none(),
        "hsts_max_age = 0 must drop the header: {r}"
    );
    // The same block covers responses the cache did not bake: a 404, a redirect.
    let miss = srv.curl(&["-i"], "/missing");
    assert!(status_ok(&miss, "404"), "{miss}");
    assert_eq!(header(&miss, "content-security-policy").as_deref(), Some("default-src 'self'"));
}

#[test]
fn an_invalid_config_leaves_the_running_server_untouched() {
    let srv = TestServer::start();
    assert!(status_ok(&srv.curl(&["-i"], "/"), "200"));
    // A rule that redirects a path to itself is refused at parse time, so the
    // reload never reaches the runtime.
    std::fs::write(
        &srv.cfg_path,
        format!(
            "listen = 127.0.0.1:{}\nsite localhost {{\n root = {}\n cert = {}\n key = {}\n redirect /a -> /a\n}}\n",
            srv.https,
            srv.root.display(),
            srv.cert.display(),
            srv.key.display(),
        ),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(6)); // several watcher ticks
    assert!(
        status_ok(&srv.curl(&["-i"], "/"), "200"),
        "a rejected config must not take the server down"
    );
}
