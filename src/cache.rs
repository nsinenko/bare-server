//! The in-memory content cache and the change-detection that feeds the
//! hot-reload watcher.
//!
//! At boot every document root is walked once and each file becomes a
//! set of ready-to-write responses (identity, and gzip/brotli for compressible
//! types). Serving a request is then a single `write_all` of a precomputed
//! buffer. The signature helpers (`file_signature`, `tree_signature`,
//! `tls_signature`, `sample`) let the watcher notice on-disk changes without
//! re-reading file bodies.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::{Config, HeaderConfig, Redirects, Storage, Tuning};
use crate::mime::mime_for;

/// The server-level cache/compression settings resolved once per cache build:
/// the raw `Tuning` plus the two Cache-Control header values derived from it, so
/// those strings are formatted once rather than per file. Cheap to share: each
/// `Cached` holds an `Arc` clone of whichever value applies.
pub(crate) struct Policy {
    pub(crate) t: Tuning,
    cc_immutable: Arc<str>,
    cc_revalidate: Arc<str>,
    /// The security-header block inside every cached response, rendered once
    /// from the config's `HeaderConfig`. Shared (Arc) with `Vhosts` so the
    /// on-the-fly error/redirect paths emit exactly the same headers.
    pub(crate) security_headers: Arc<str>,
    /// This site's precomputed 4xx/5xx responses, carrying the same
    /// `security_headers` block above. Built here rather than per request, so an
    /// error costs one `write_all` like a cache hit does.
    pub(crate) errors: ErrorPages,
    /// Memory (bodies in RAM) or Disk (bodies snapshotted under `disk_cache`).
    pub(crate) storage: Storage,
    /// Root directory for the on-disk snapshot in Disk mode; unused in Memory.
    pub(crate) disk_cache: PathBuf,
}

impl Policy {
    /// Build a policy with the default (compile-time-equivalent) response
    /// headers and in-memory storage. Used throughout the tests, which do not
    /// vary header or storage config; production always goes through
    /// `with_headers`.
    #[cfg(test)]
    pub(crate) fn new(t: Tuning) -> Policy {
        Policy::with_headers(t, &HeaderConfig::default(), Storage::Memory, PathBuf::new())
    }

    /// Build a policy with an explicit response-header and storage configuration.
    pub(crate) fn with_headers(
        t: Tuning,
        h: &HeaderConfig,
        storage: Storage,
        disk_cache: PathBuf,
    ) -> Policy {
        let security_headers: Arc<str> = h.render().into();
        Policy {
            t,
            cc_immutable: format!("public, max-age={}, immutable", t.immutable_max_age).into(),
            cc_revalidate: format!("public, max-age={}, must-revalidate", t.cache_max_age).into(),
            errors: ErrorPages::new(&security_headers),
            security_headers,
            storage,
            disk_cache,
        }
    }

    /// Caching policy, derived from the URL alone. The server knows nothing
    /// about any particular site's layout.
    ///
    /// A fingerprinted URL names one exact set of bytes: changing the content
    /// changes the hash, and therefore the URL. That is what makes `immutable`
    /// safe, and it is the *only* thing that does. Pinning an un-hashed path
    /// strands the old bytes in every client's cache until they expire, with no
    /// way to bust them. So everything else revalidates instead, which the ETag
    /// makes cheap (a 304 is a header round trip, no body).
    fn cache_control_for(&self, url: &str) -> Arc<str> {
        if is_fingerprinted(url) {
            Arc::clone(&self.cc_immutable)
        } else {
            Arc::clone(&self.cc_revalidate)
        }
    }
}

/// One precomputed response encoding: the complete keep-alive response
/// (status line + headers + body) as a single contiguous buffer, so serving is
/// one `write_all`: one TLS record, one syscall, zero per-request allocation.
/// `header_len` marks where the body starts (for HEAD and the rare close path).
pub(crate) struct Variant {
    pub(crate) full_ka: Vec<u8>,
    pub(crate) header_len: usize,
    pub(crate) etag: String, // strong validator (content hash), also inside the header
    pub(crate) encoding: Option<&'static str>, // Content-Encoding, echoed on 304s
}

/// One precomputed response in one `Connection` form. `header_len` marks where
/// the body starts, so a HEAD answer is the same buffer truncated.
struct Prebuilt {
    full: Vec<u8>,
    header_len: usize,
}

/// One precomputed status response, in both `Connection` forms. Errors are the
/// one response class the server generates itself, and every input is fixed at
/// boot, so the server precomputes them exactly as it does content. See `Variant`.
pub(crate) struct StatusResponse {
    ka: Prebuilt,
    close: Prebuilt,
}

impl StatusResponse {
    /// The exact bytes to write for one request. `keep_alive` picks the
    /// `Connection` form. `is_head` drops the body (RFC 9112 6.3) while the
    /// header keeps advertising its real length (RFC 9110 9.3.2).
    pub(crate) fn bytes(&self, keep_alive: bool, is_head: bool) -> &[u8] {
        let p = if keep_alive { &self.ka } else { &self.close };
        if is_head {
            &p.full[..p.header_len]
        } else {
            &p.full
        }
    }

    fn retained_bytes(&self) -> usize {
        self.ka.full.len() + self.close.full.len()
    }
}

/// Every status this server generates on its own, built once per rendered
/// security-header block. There is one set per site (so a site's `csp` covers
/// its errors) and one server-level set for what is answered before a host
/// resolves.
pub(crate) struct ErrorPages {
    pub(crate) bad_request: StatusResponse,          // 400
    pub(crate) not_found: StatusResponse,            // 404
    pub(crate) method_not_allowed: StatusResponse,   // 405
    pub(crate) request_timeout: StatusResponse,      // 408
    pub(crate) headers_too_large: StatusResponse,    // 431
    pub(crate) internal_error: StatusResponse,       // 500
}

impl ErrorPages {
    pub(crate) fn new(security_headers: &str) -> ErrorPages {
        ErrorPages {
            bad_request: build_status(400, "Bad Request", security_headers),
            not_found: build_status(404, "Not Found", security_headers),
            method_not_allowed: build_status(405, "Method Not Allowed", security_headers),
            request_timeout: build_status(408, "Request Timeout", security_headers),
            headers_too_large: build_status(
                431,
                "Request Header Fields Too Large",
                security_headers,
            ),
            internal_error: build_status(500, "Internal Server Error", security_headers),
        }
    }

    /// Resident bytes this set holds. Charged against `max_total_bytes` by the
    /// callers that build a site, because the budget is documented as every byte
    /// actually retained, not only the bytes of cached files.
    pub(crate) fn retained_bytes(&self) -> usize {
        self.bad_request.retained_bytes()
            + self.not_found.retained_bytes()
            + self.method_not_allowed.retained_bytes()
            + self.request_timeout.retained_bytes()
            + self.headers_too_large.retained_bytes()
            + self.internal_error.retained_bytes()
    }
}

/// Build both `Connection` forms of one generated status response.
///
/// `Cache-Control: no-store` is load-bearing. A 404 with no `Cache-Control` is
/// heuristically cacheable (RFC 9111 4.2.2), so a shared cache is free to keep
/// answering 404 for a URL after the page behind it exists. The server cannot
/// know how long that would last, so it stores nothing.
fn build_status(code: u16, reason: &str, security_headers: &str) -> StatusResponse {
    let body = format!("<!doctype html><title>{code} {reason}</title><h1>{code} {reason}</h1>\n");
    // Headers one status must carry beyond the common set. RFC 9110 15.5.6 makes
    // `Allow` mandatory on a 405 from an origin server: without it a client sees
    // the refusal but cannot learn which methods exist. This server answers only
    // GET and HEAD, so the list is fixed.
    let required = match code {
        405 => "Allow: GET, HEAD\r\n",
        _ => "",
    };
    let form = |conn: &str| {
        let head = format!(
            "HTTP/1.1 {code} {reason}\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Cache-Control: no-store\r\n\
             Connection: {conn}\r\n\
             {required}\
             {security_headers}\r\n",
            body.len()
        );
        let header_len = head.len();
        let mut full = Vec::with_capacity(header_len + body.len());
        full.extend_from_slice(head.as_bytes());
        full.extend_from_slice(body.as_bytes());
        Prebuilt { full, header_len }
    };
    StatusResponse { ka: form("keep-alive"), close: form("close") }
}

/// A cached file, in memory: its identity response plus, for compressible
/// types, gzip and brotli responses, all precompressed and prebuilt once at
/// boot, so compression costs nothing per request.
pub(crate) struct MemEntry {
    pub(crate) identity: Variant,
    pub(crate) gzip: Option<Variant>,
    pub(crate) br: Option<Variant>,
    pub(crate) cache_control: Arc<str>, // also echoed on 304s
    pub(crate) vary: bool,                  // ditto: a 304 must carry the same Vary as the 200
}

/// One precomputed response encoding whose body lives on disk (Disk storage).
/// Only the header (with Content-Length and ETag) is held in RAM; the body is
/// streamed from `path` at serve time, so the OS page cache does the buffering.
pub(crate) struct DiskVariant {
    pub(crate) header_ka: Vec<u8>, // status line + headers, Connection: keep-alive, ends \r\n\r\n
    pub(crate) path: PathBuf,      // absolute path to the body file in the build snapshot
    pub(crate) len: u64,           // body length (== Content-Length)
    pub(crate) etag: String,
    pub(crate) encoding: Option<&'static str>,
}

/// The disk-backed analogue of `MemEntry`: the identity body and any sidecars
/// live on disk under the build snapshot; only headers/validators are in RAM.
pub(crate) struct DiskEntry {
    pub(crate) identity: DiskVariant,
    pub(crate) gzip: Option<DiskVariant>,
    pub(crate) br: Option<DiskVariant>,
    pub(crate) cache_control: Arc<str>,
    pub(crate) vary: bool,
}

/// One cached URL, in whichever storage backend the runtime was built with.
pub(crate) enum Cached {
    Mem(MemEntry),
    Disk(DiskEntry),
}

impl Cached {
    /// Resident (RAM) bytes this entry holds: full precomputed buffers in Memory
    /// mode, just the headers in Disk mode (bodies are on disk). Feeds the
    /// `max_total_bytes` budget and the reload accounting.
    pub(crate) fn retained_bytes(&self) -> usize {
        match self {
            Cached::Mem(m) => {
                m.identity.full_ka.len()
                    + m.gzip.as_ref().map_or(0, |v| v.full_ka.len())
                    + m.br.as_ref().map_or(0, |v| v.full_ka.len())
            }
            Cached::Disk(d) => {
                d.identity.header_ka.len()
                    + d.gzip.as_ref().map_or(0, |v| v.header_ka.len())
                    + d.br.as_ref().map_or(0, |v| v.header_ka.len())
            }
        }
    }
}
pub(crate) type Cache = HashMap<String, Cached>;

/// An owned on-disk build snapshot directory. Dropping it removes the directory
/// and everything under it, so a superseded Disk-mode cache cleans up its
/// snapshot once the last in-flight request holding it finishes. This is the same
/// lifetime discipline the in-memory Arc already gives content.
pub(crate) struct BuildDir(PathBuf);
impl Drop for BuildDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0); // best-effort; nothing to do on failure
    }
}

/// A built cache plus, in Disk mode, ownership of the snapshot directory its
/// entries point into. The watcher swaps this as one `Arc`, so an in-flight
/// request pins both the index and the on-disk files it is streaming.
pub(crate) struct SiteCache {
    pub(crate) map: Cache,
    _build_dir: Option<BuildDir>,
}

impl SiteCache {
    /// The cache of a site with no document root: a host that only issues
    /// redirects still needs a `Site`, and giving it an empty map keeps every
    /// lookup on the serve path identical instead of special-casing it.
    pub(crate) fn empty() -> SiteCache {
        SiteCache { map: Cache::new(), _build_dir: None }
    }
}

/// One live virtual host. `cache` is swapped by the hot-reload watcher; a reader
/// clones the current `Arc` under a brief read lock and holds it for the whole
/// request, so a swap never disturbs an in-flight response (zero downtime).
pub(crate) struct Site {
    /// `None` for a host that serves no content of its own. Such a host exists only to
    /// terminate TLS and answer with its redirect rules.
    pub(crate) root: Option<PathBuf>,
    pub(crate) cache: RwLock<Arc<SiteCache>>,
    /// Serve this host's plain-HTTP traffic as a 301 to https:// rather than
    /// serving content over :80. See `SiteConfig::force_ssl`.
    pub(crate) force_ssl: bool,
    /// Fold the `.html` spellings of a URL onto the canonical directory form.
    /// See `SiteConfig::canonical_urls`.
    pub(crate) canonical_urls: bool,
    /// This site's path redirect rules, consulted before its content.
    pub(crate) redirects: Redirects,
    /// This site's resolved cache/compression/header settings. Held here rather
    /// than once per process because a site block may override any of them, and
    /// the watcher needs the right one to rebuild this site's content with.
    pub(crate) policy: Arc<Policy>,
}
/// Virtual hosting: lowercased host name -> live site.
pub(crate) type Sites = HashMap<String, Arc<Site>>;

/// The full host table. A name that only redirects (www -> apex) is an ordinary
/// `Site` with no root and a catch-all rule, so there is exactly one kind of
/// vhost here, and exactly one path through the server that emits a redirect.
pub(crate) struct Vhosts {
    pub(crate) sites: Sites,
    /// The HTTPS listener's port ("443", "8443", ...). Emitted in redirect
    /// `Location` authorities, omitted when it is the scheme default (443).
    pub(crate) https_port: String,
    /// The plain-HTTP listener's port, for same-scheme directory redirects on a
    /// site that serves over :80. Empty when there is no plain listener;
    /// omitted when it is 80.
    pub(crate) http_port: String,
    /// The responses sent before any site is known: a 400 on a malformed request
    /// head, a 404 for an unconfigured Host, and the 408/431 the read loop
    /// answers with. All of them are errors, so the server-level `HeaderConfig`
    /// reaches the wire inside these buffers rather than as a field of its
    /// own. Once a site resolves, its own precomputed set applies instead.
    pub(crate) errors: ErrorPages,
}

/// True if a URL's filename carries a content hash, by convention: the last
/// `-`-separated segment of the stem is 8+ hex digits, e.g.
/// `/style-0667c2b357.css` or `/assets/fonts/source-sans-3-400-a1b2c3d4e5.woff2`.
///
/// The 8-digit floor is what keeps ordinary words from matching: a stem ending
/// in `-latin` or `-normal` is not hex, and short hex-ish words like `-faced`
/// are too short to qualify. An all-decimal suffix is rejected as well: dates
/// and version numbers (`export-20240115.json`) are hex-clean but do *not*
/// change with the bytes, and pinning one strands stale content for a year.
/// A real hash that happens to be all digits merely revalidates: a wasted
/// round trip, never a wrong answer, so the heuristic errs in the safe
/// direction.
fn is_fingerprinted(url: &str) -> bool {
    let file = match url.rsplit_once('/') {
        Some((_, f)) => f,
        None => url,
    };
    let stem = match file.rsplit_once('.') {
        Some((s, _)) => s,
        None => return false, // no extension: not a build artifact
    };
    match stem.rsplit_once('-') {
        Some((_, hash)) => {
            hash.len() >= 8
                && hash.bytes().all(|b| b.is_ascii_hexdigit())
                && !hash.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Strong ETag from the (already-encoded) body: FNV-1a 64 + length, hex.
/// Content is immutable in memory, so a content hash is an exact validator.
fn etag_for(body: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in body {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:x}-{:x}", body.len(), h)
}

fn is_compressible(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime.contains("javascript")
        || mime.contains("json")
        || mime.contains("xml")
        || mime.contains("svg")
        || mime.contains("wasm")
}

fn gzip_compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

fn brotli_compress(data: &[u8], quality: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        // lgwin 22; quality is the boot-cost knob (11 = max, slowest).
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
        let _ = w.write_all(data);
    }
    out
}

/// Build the response header block (status line + headers, ending with the
/// blank line) for a body of `body_len` bytes with validator `etag`. Shared by
/// the in-memory variant builder and the disk-backed one, so both backends emit
/// byte-identical headers.
fn build_header(
    mime: &str,
    body_len: usize,
    etag: &str,
    encoding: Option<&'static str>,
    vary: bool,
    cache_control: &str,
    security_headers: &str,
) -> String {
    let mut h = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nContent-Length: {body_len}\r\nETag: \"{etag}\"\r\n"
    );
    if let Some(enc) = encoding {
        h.push_str("Content-Encoding: ");
        h.push_str(enc);
        h.push_str("\r\n");
    }
    if vary {
        h.push_str("Vary: Accept-Encoding\r\n");
    }
    h.push_str("Cache-Control: ");
    h.push_str(cache_control);
    h.push_str("\r\n");
    h.push_str("Connection: keep-alive\r\n");
    h.push_str(security_headers);
    h.push_str("\r\n");
    h
}

/// Build a full keep-alive response (header + body) for one body/encoding.
fn build_variant(
    mime: &str,
    body: &[u8],
    encoding: Option<&'static str>,
    vary: bool,
    cache_control: &str,
    security_headers: &str,
) -> Variant {
    let etag = etag_for(body);
    let h = build_header(mime, body.len(), &etag, encoding, vary, cache_control, security_headers);
    let header_len = h.len();
    let mut full_ka = Vec::with_capacity(header_len + body.len());
    full_ka.extend_from_slice(h.as_bytes());
    full_ka.extend_from_slice(body);
    Variant { full_ka, header_len, etag, encoding }
}

/// Which compressed variants a compressible file should get, per policy.
/// Returns the gzip and brotli bodies (each present only when produced and
/// actually smaller than the source). Shared by both storage backends.
fn compress_variants(mime: &str, data: &[u8], p: &Policy) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    if !(p.t.compression && is_compressible(mime) && data.len() >= p.t.min_compress_bytes) {
        return (None, None);
    }
    // gzip gets the high ceiling (it is cheap); brotli the low one (it is not).
    // A large bundle between the two limits is still served gzipped. Dropping
    // it to identity-only would have put megabytes back on the wire for no
    // boot-time saving worth the name.
    let gz = (data.len() <= p.t.max_gzip_bytes)
        .then(|| gzip_compress(data, p.t.gzip_level))
        .filter(|g| g.len() < data.len());
    let br = (data.len() <= p.t.max_brotli_bytes)
        .then(|| brotli_compress(data, p.t.brotli_quality))
        .filter(|b| b.len() < data.len());
    (gz, br)
}

/// Build the in-memory cache entry for one file: identity always, plus
/// gzip/brotli when the type is compressible and the compressed form is smaller.
fn make_cached(url: &str, mime: &str, data: &[u8], p: &Policy) -> MemEntry {
    let cc = p.cache_control_for(url);
    let (gz, brb) = compress_variants(mime, data, p);
    let vary = gz.is_some() || brb.is_some();
    let sh = &p.security_headers;
    let gzip = gz.map(|g| build_variant(mime, &g, Some("gzip"), true, &cc, sh));
    let br = brb.map(|b| build_variant(mime, &b, Some("br"), true, &cc, sh));
    let identity = build_variant(mime, data, None, vary, &cc, sh);
    MemEntry { identity, gzip, br, cache_control: cc, vary }
}

/// Snapshot one file's body (and any compressed sidecars) into `build_dir`,
/// mirroring the URL path, and return a disk-backed entry whose variants point
/// at those files. The header (Content-Length, ETag, all) is precomputed just
/// as in memory mode; only the body is left on disk to be streamed.
fn make_disk_entry(
    url: &str,
    mime: &str,
    data: &[u8],
    p: &Policy,
    build_dir: &Path,
) -> std::io::Result<DiskEntry> {
    let cc = p.cache_control_for(url);
    let (gz, brb) = compress_variants(mime, data, p);
    let vary = gz.is_some() || brb.is_some();
    let sh = &p.security_headers;

    // Mirror the URL under a per-encoding namespace:
    //   "/blog/x.html" -> "<build>/identity/blog/x.html", "<build>/gzip/blog/x.html", ...
    //
    // Appending ".gz"/".br" to a shared base instead would collide with a real
    // file of that name in the document root, which is exactly what a site that
    // ships pre-compressed sidecars has: `app.js` and `app.js.gz` both resolve to
    // "<build>/app.js.gz", and whichever the directory walk reaches last silently
    // overwrites the other's body while both keep their own Content-Length and
    // ETag in RAM. The result is a response that under-delivers its declared
    // length on a connection that stays open (a desync), or serves one asset's
    // bytes under the other's validator. Namespacing by encoding makes the
    // mapping injective: URLs are unique cache keys, so one URL is one file in
    // one namespace, whatever it is named.
    let ns = |dir: &str| -> std::io::Result<PathBuf> {
        let p = build_dir.join(dir).join(url.trim_start_matches('/'));
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(p)
    };

    let write_variant = |path: PathBuf,
                         body: &[u8],
                         encoding: Option<&'static str>|
     -> std::io::Result<DiskVariant> {
        let etag = etag_for(body);
        let header = build_header(mime, body.len(), &etag, encoding, vary, &cc, sh);
        fs::write(&path, body)?;
        Ok(DiskVariant {
            header_ka: header.into_bytes(),
            path,
            len: body.len() as u64,
            etag,
            encoding,
        })
    };

    let identity = write_variant(ns("identity")?, data, None)?;
    let gzip = match gz {
        Some(g) => Some(write_variant(ns("gzip")?, &g, Some("gzip"))?),
        None => None,
    };
    let br = match brb {
        Some(b) => Some(write_variant(ns("br")?, &b, Some("br"))?),
        None => None,
    };
    Ok(DiskEntry { identity, gzip, br, cache_control: cc, vary })
}

/// Monotonic build sequence, so each (re)build gets its own snapshot directory
/// and a superseded one can be removed without disturbing in-flight requests.
static BUILD_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Remove leftover `build-*` snapshot directories from a previous run. Drop
/// cleans them up on a graceful swap, but a process killed mid-life leaves its
/// live snapshot behind, and `BUILD_SEQ` restarts at 0, so without this a
/// restart could write into a stale directory or slowly accumulate orphans.
/// Best-effort; called once at startup for the configured `disk_cache`.
pub(crate) fn clear_stale_builds(disk_cache: &Path) {
    if let Ok(entries) = fs::read_dir(disk_cache) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("build-") {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
}

/// Hidden entries are skipped, with one exception: `.well-known` is a
/// registered URI prefix (RFC 8615), not an editor artifact. It carries
/// security.txt and the ACME http-01 challenge, so skipping it silently makes
/// certificate renewal impossible. Both `walk` and `dir_signature` use this so
/// the hot-reload watcher does not go blind to a directory the cache serves.
fn is_hidden(name: &str) -> bool {
    name.starts_with('.') && name != ".well-known"
}

/// Build a fresh cache for `root`, charging `total` (which the caller carries
/// across every site, so the budget is global rather than per-site). Returns
/// None if it exceeds max_total_bytes, so a hot reload can abort and keep
/// serving the old cache rather than crash. In Disk mode it also allocates a
/// fresh snapshot directory under `disk_cache`, owned by the returned
/// `SiteCache` and removed when that cache is dropped.
pub(crate) fn build_cache(root: &Path, total: &mut usize, p: &Policy) -> Option<SiteCache> {
    // Fail closed on the root itself. `walk` treats an unreadable directory as
    // "skip, not fatal", which is right for a subdirectory but disastrous for
    // the root: a root that vanished mid-deploy (symlink swap, brief chmod)
    // would otherwise yield an empty cache that the watcher installs, 404ing
    // the entire site until restart. Keeping the old cache is always better.
    if !root.is_dir() || fs::read_dir(root).is_err() {
        return None;
    }
    // In Disk mode, each build gets its own snapshot dir so a superseded one is
    // removed (on BuildDir drop) without disturbing in-flight requests.
    let build_dir = match p.storage {
        Storage::Memory => None,
        Storage::Disk => {
            let seq = BUILD_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = p.disk_cache.join(format!("build-{seq}"));
            if let Err(e) = fs::create_dir_all(&dir) {
                eprintln!("bare-server: cannot create disk snapshot {}: {e}", dir.display());
                return None;
            }
            Some(BuildDir(dir))
        }
    };
    let mut map = HashMap::new();
    let ok = walk(root, "", &mut map, total, p, build_dir.as_ref().map(|b| b.0.as_path()));
    if ok {
        Some(SiteCache { map, _build_dir: build_dir })
    } else {
        None // build_dir drops here, cleaning up any partial snapshot
    }
}

/// Retained (RAM) bytes of a built cache: full buffers in Memory mode, just the
/// headers in Disk mode. Used by the watcher to seed a hot-reload's budget with
/// what the other live roots already hold, so the max_total_bytes ceiling
/// survives reloads.
pub(crate) fn cache_bytes(cache: &Cache) -> usize {
    cache.values().map(|c| c.retained_bytes()).sum()
}

/// Recursively load `dir` into `map`. `prefix` is its URL prefix ("" for root).
/// Symlinks are skipped so nothing outside the root can be pulled in. When
/// `build_dir` is Some, bodies are snapshotted there (Disk mode) instead of held
/// in RAM. Returns false if the RAM budget was exceeded (Memory mode only).
fn walk(
    dir: &Path,
    prefix: &str,
    map: &mut Cache,
    total: &mut usize,
    p: &Policy,
    build_dir: Option<&Path>,
) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // Unreadable subdirectory: fail the whole build. Skipping it yields a
        // truncated cache promoted with a normal "cached N files" line, so a
        // deploy that lands one subtree with the wrong ownership 404s every asset
        // under it while the log reports success. Failing closed keeps the
        // previous cache on a reload and refuses to boot on a fresh start, which
        // is the same bargain `build_cache` already makes for the root itself.
        Err(e) => {
            eprintln!("bare-server: cannot read directory {}: {e}", dir.display());
            return false;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_hidden(&name) {
            continue;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue; // never follow symlinks
        }
        let url = format!("{prefix}/{name}");
        if meta.is_dir() {
            if !walk(&path, &url, map, total, p, build_dir) {
                return false;
            }
        } else if meta.is_file() {
            let size = meta.len() as usize;
            if size > p.t.max_file_size {
                eprintln!("bare-server: skipping oversized {url}");
                continue;
            }
            // Cheap pre-read guard: never read a file that cannot possibly fit
            // the RAM budget. Disk mode holds no bodies in RAM, so the budget
            // (a RAM ceiling) does not gate it. Only disk space does.
            if build_dir.is_none() && *total + size > p.t.max_total_bytes {
                eprintln!("bare-server: cache exceeds max_total_bytes at {url}");
                return false;
            }
            let data = match fs::read(&path) {
                Ok(d) => d,
                Err(_) => {
                    eprintln!("bare-server: cannot read {url}");
                    continue;
                }
            };
            let cached = match build_dir {
                None => Cached::Mem(make_cached(&url, mime_for(&url), &data, p)),
                Some(bd) => match make_disk_entry(&url, mime_for(&url), &data, p, bd) {
                    Ok(e) => Cached::Disk(e),
                    Err(e) => {
                        eprintln!("bare-server: cannot snapshot {url} to disk: {e}");
                        continue;
                    }
                },
            };
            // Charge what is actually retained in RAM, not the source bytes:
            // Memory mode holds up to three header+body buffers per file; Disk
            // mode holds only the (tiny) headers. Counting the source would
            // overshoot Disk and undershoot Memory.
            let stored = cached.retained_bytes();
            if build_dir.is_none() && *total + stored > p.t.max_total_bytes {
                eprintln!("bare-server: cache exceeds max_total_bytes at {url}");
                return false;
            }
            *total += stored;
            map.insert(url, cached);
        }
    }
    true
}

/// A cheap content-signature of a tree: folds each file's (sorted path, size,
/// mtime) into a hash. Used by the watcher to detect changes without reading
/// file bodies. Mirrors `walk`'s rules (skip dotfiles and symlinks).
fn dir_signature(dir: &Path, hash: &mut u64) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut list: Vec<_> = entries.flatten().collect();
    list.sort_by_key(|e| e.file_name()); // stable order -> stable signature
    for entry in list {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if is_hidden(&name) {
            continue;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        for b in name.bytes() {
            *hash ^= b as u64;
            *hash = hash.wrapping_mul(0x100000001b3);
        }
        if meta.is_dir() {
            dir_signature(&path, hash);
        } else if meta.is_file() {
            let mt = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            *hash ^= meta.len();
            *hash = hash.wrapping_mul(0x100000001b3);
            *hash ^= mt;
            *hash = hash.wrapping_mul(0x100000001b3);
        }
    }
}

/// Signature of the config file itself (size + mtime), for change detection.
pub(crate) fn file_signature(path: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    if let Ok(m) = fs::metadata(path) {
        let mt = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        h ^= m.len();
        h = h.wrapping_mul(0x100000001b3);
        h ^= mt;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub(crate) fn tree_signature(root: &Path) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    dir_signature(root, &mut h);
    h
}

/// Every cert and key file the config names, in config order.
fn tls_paths(cfg: &Config) -> Vec<String> {
    // Every site terminates TLS, including the ones that only redirect, so this
    // is simply every site's pair.
    let mut v = Vec::with_capacity(2 * cfg.sites.len());
    for s in &cfg.sites {
        v.push(s.cert.clone());
        v.push(s.key.clone());
    }
    v
}

/// Combined signature of the TLS material. Folded in order rather than XORed so
/// that two sites sharing one cert file don't cancel each other out.
/// `fs::metadata` follows symlinks, so a cert path that points through a
/// symlink tracks the file it currently resolves to.
pub(crate) fn tls_signature(paths: &[String]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for p in paths {
        h ^= file_signature(p);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// What the watcher must sample BEFORE a runtime is built from `cfg`: the config
/// file's own signature, the TLS paths with their signature, and every document
/// root's tree signature.
///
/// The ordering is the whole point. `build_runtime` spends seconds compressing,
/// and a file that lands while `build_cache` is walking is absent from the cache
/// it produces. Sampling *after* the build would record that file as already
/// applied, and since nothing on disk changes again the watcher would never
/// rebuild: the URL 404s until an unrelated edit perturbs the tree. Sampling
/// first leaves `now != applied`, so the very next tick picks it up. The same
/// hazard applies to `server.conf` itself: an operator who rewrites it during
/// the boot build must not have that edit silently swallowed, so its signature
/// is captured here too, not read fresh when the watcher starts.
pub(crate) struct Sampled {
    pub(crate) config: u64,
    pub(crate) tls_files: Vec<String>,
    pub(crate) tls: u64,
    pub(crate) trees: HashMap<String, u64>,
    pub(crate) links: Vec<(String, PathBuf)>,
}

/// What each configured `root` currently resolves to. `build_vhosts` canonicalises
/// the root and keeps only the *resolved* directory, which is what gets watched.
/// so with the usual release layout (`/srv/www -> /srv/releases/42`) the watcher
/// polls release 42 forever and a symlink flip to release 43 changes nothing under
/// the path it is looking at. Recording the link target lets the watcher notice the
/// flip and re-resolve. Kept as a Vec so two sites sharing a configured path each
/// get an entry rather than silently collapsing.
pub(crate) fn root_links(cfg: &Config) -> Vec<(String, PathBuf)> {
    cfg.sites
        .iter()
        .filter_map(|s| s.root.as_ref())
        .map(|s| (s.clone(), fs::canonicalize(s).unwrap_or_else(|_| PathBuf::from(s))))
        .collect()
}

/// `root_links` for the config file as it currently reads. `None` when the file
/// cannot be parsed: a half-written config is not evidence that a root moved,
/// and the config-signature path already handles (and retries) that case.
pub(crate) fn root_links_of(config_path: &str) -> Option<Vec<(String, PathBuf)>> {
    crate::config::load_config(config_path).ok().map(|c| root_links(&c))
}

pub(crate) fn sample(config_path: &str, cfg: &Config) -> Sampled {
    let config = file_signature(config_path);
    let tls_files = tls_paths(cfg);
    let tls = tls_signature(&tls_files);
    let mut trees: HashMap<String, u64> = HashMap::new();
    for s in cfg.sites.iter().filter_map(|s| s.root.as_ref()) {
        // Key by the canonical root, as build_vhosts does: several hostnames can
        // alias one root, and it is hashed once here. A redirect-only site has
        // no root and so no tree to watch.
        let root = fs::canonicalize(s).unwrap_or_else(|_| PathBuf::from(s));
        trees.entry(root.display().to_string()).or_insert_with(|| tree_signature(&root));
    }
    Sampled { config, tls_files, tls, trees, links: root_links(cfg) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> Policy {
        Policy::new(Tuning::default())
    }

    #[test]
    fn a_status_response_is_one_buffer_per_connection_form() {
        let e = ErrorPages::new("X-Site: yes\r\n");
        let ka = String::from_utf8_lossy(e.not_found.bytes(true, false)).into_owned();
        let close = String::from_utf8_lossy(e.not_found.bytes(false, false)).into_owned();
        assert!(ka.starts_with("HTTP/1.1 404 Not Found\r\n"), "{ka}");
        assert!(ka.contains("Connection: keep-alive\r\n"), "{ka}");
        assert!(close.contains("Connection: close\r\n"), "{close}");
        // The site's own header block is inside the buffer, so an error carries
        // the same CSP and HSTS as that site's 200s.
        assert!(ka.contains("X-Site: yes\r\n"), "{ka}");
        // A 404 must never be stored: see `build_status`.
        assert!(ka.contains("Cache-Control: no-store\r\n"), "{ka}");
        // Header and body are one buffer, which is the whole point.
        let (head, body) = ka.split_once("\r\n\r\n").expect("header terminator");
        assert_eq!(body, "<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>\n");
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())), "{head}");
    }

    #[test]
    fn a_head_answer_is_the_same_buffer_without_the_body() {
        let e = ErrorPages::new("");
        for keep_alive in [true, false] {
            let full = e.internal_error.bytes(keep_alive, false);
            let head = e.internal_error.bytes(keep_alive, true);
            assert!(full.starts_with(head), "a HEAD answer is a prefix of the GET answer");
            assert!(head.ends_with(b"\r\n\r\n"), "it stops at the header terminator");
            assert!(full.len() > head.len(), "the GET answer carries a body");
        }
        // Both forms are retained, and both are charged to the RAM budget.
        assert_eq!(
            e.internal_error.retained_bytes(),
            e.internal_error.bytes(true, false).len() + e.internal_error.bytes(false, false).len()
        );
    }

    #[test]
    fn every_generated_status_is_precomputed() {
        // One buffer per status this server emits. A status added to the serve
        // path without a buffer here would not compile, so this only has to
        // check that each one is really populated.
        let e = ErrorPages::new("");
        for (resp, line) in [
            (&e.bad_request, "HTTP/1.1 400 Bad Request\r\n"),
            (&e.not_found, "HTTP/1.1 404 Not Found\r\n"),
            (&e.method_not_allowed, "HTTP/1.1 405 Method Not Allowed\r\n"),
            (&e.request_timeout, "HTTP/1.1 408 Request Timeout\r\n"),
            (&e.headers_too_large, "HTTP/1.1 431 Request Header Fields Too Large\r\n"),
            (&e.internal_error, "HTTP/1.1 500 Internal Server Error\r\n"),
        ] {
            assert!(resp.bytes(true, false).starts_with(line.as_bytes()), "missing {line}");
        }
        assert!(e.retained_bytes() > 0);
    }

    #[test]
    fn the_405_names_the_methods_it_allows() {
        // RFC 9110 15.5.6: an origin server that refuses a method MUST say which
        // methods it supports, or the client cannot adapt. Both connection forms
        // carry it, and it sits in the header block, not the body.
        let e = ErrorPages::new("");
        for keep_alive in [true, false] {
            let head = String::from_utf8_lossy(e.method_not_allowed.bytes(keep_alive, true))
                .to_string();
            assert!(head.contains("Allow: GET, HEAD\r\n"), "{head}");
        }
        // And no other status claims to allow anything.
        for resp in [&e.bad_request, &e.not_found, &e.request_timeout, &e.internal_error] {
            let full = String::from_utf8_lossy(resp.bytes(true, false)).to_string();
            assert!(!full.contains("Allow:"), "{full}");
        }
    }

    #[test]
    fn fingerprinted_urls_are_detected() {
        for url in [
            "/style-0667c2b357.css",
            "/assets/fonts/source-sans-3-400-normal-latin-a1b2c3d4e5.woff2",
            "/app-deadbeef.js",
            "/x-0123456789abcdef.css", // long hash
            "/x-ABCDEF12.css",         // uppercase hex
        ] {
            assert!(is_fingerprinted(url), "expected fingerprinted: {url}");
        }
    }

    #[test]
    fn plain_urls_are_not_pinned() {
        // A false positive here would pin a mutable file for a year, so the
        // real-world un-hashed names this server serves are all checked.
        for url in [
            "/",
            "/style.css",
            "/favicon.ico",
            "/site.webmanifest",
            "/about/index.html",
            "/assets/fonts/source-sans-3-400-normal-latin.woff2",
            "/assets/fonts/dm-serif-display-400-italic-latin.woff2",
            "/assets/images/og-default.png",
            "/assets/images/favicons/android-chrome-192x192.png",
            "/robots.txt",
            "/llms.txt",
            "/sitemap.xml",
            "/reports/export-20240115.json", // date suffix, not a content hash
        ] {
            assert!(!is_fingerprinted(url), "must NOT be pinned: {url}");
        }
    }

    #[test]
    fn short_or_nonhex_suffixes_do_not_qualify() {
        assert!(!is_fingerprinted("/x-abc123.css")); // 6 chars: too short
        assert!(!is_fingerprinted("/x-1234567.css")); // 7 chars: too short
        assert!(is_fingerprinted("/x-1234567a.css")); // 8: the boundary
        assert!(!is_fingerprinted("/x-12345678.css")); // all-decimal: a date, not a hash
        assert!(!is_fingerprinted("/x-latinlatin.css")); // right length, not hex
        assert!(!is_fingerprinted("/noextension"));
        assert!(!is_fingerprinted("/nodash.css"));
    }

    #[test]
    fn policy_follows_fingerprinting() {
        assert!(pol().cache_control_for("/style-0667c2b357.css").contains("immutable"));
        assert!(pol().cache_control_for("/style.css").contains("must-revalidate"));
        assert!(!pol().cache_control_for("/style.css").contains("immutable"));
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::testutil::TempDir;

    fn pol() -> Policy {
        Policy::new(Tuning::default())
    }

    #[test]
    fn etag_is_deterministic_and_content_sensitive() {
        assert_eq!(etag_for(b"hello"), etag_for(b"hello"));
        assert_ne!(etag_for(b"hello"), etag_for(b"hellp"));
        // Format is "<len-hex>-<hash-hex>".
        let e = etag_for(b"abc");
        assert!(e.starts_with("3-"), "{e}"); // len 3
        assert!(e[2..].bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn compressibility_matches_types() {
        for m in [
            "text/html; charset=utf-8",
            "text/plain",
            "application/javascript",
            "application/json",
            "application/xml",
            "image/svg+xml",
            "application/wasm",
        ] {
            assert!(is_compressible(m), "should compress: {m}");
        }
        for m in ["image/png", "image/jpeg", "font/woff2", "application/octet-stream"] {
            assert!(!is_compressible(m), "should NOT compress: {m}");
        }
    }

    #[test]
    fn hidden_skips_dotfiles_except_well_known() {
        assert!(is_hidden(".git"));
        assert!(is_hidden(".env"));
        assert!(!is_hidden(".well-known"));
        assert!(!is_hidden("index.html"));
    }

    #[test]
    fn variant_header_is_well_formed() {
        let v = build_variant("text/css", b"body{}", Some("gzip"), true, "no-store", "X-Test: 1\r\n");
        let head = String::from_utf8(v.full_ka[..v.header_len].to_vec()).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("Content-Type: text/css\r\n"));
        assert!(head.contains("X-Test: 1\r\n"), "security headers are appended");
        assert!(head.contains("Content-Length: 6\r\n"));
        assert!(head.contains(&format!("ETag: \"{}\"\r\n", v.etag)));
        assert!(head.contains("Content-Encoding: gzip\r\n"));
        assert!(head.contains("Vary: Accept-Encoding\r\n"));
        assert!(head.contains("Cache-Control: no-store\r\n"));
        assert!(head.contains("Connection: keep-alive\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
        // full_ka = header + body, and header_len is the split point.
        assert_eq!(&v.full_ka[v.header_len..], b"body{}");
        assert_eq!(v.encoding, Some("gzip"));
    }

    #[test]
    fn identity_variant_omits_encoding_line() {
        let v = build_variant("text/plain", b"x", None, false, "no-store", "");
        let head = String::from_utf8(v.full_ka[..v.header_len].to_vec()).unwrap();
        assert!(!head.contains("Content-Encoding"));
        assert!(!head.contains("Vary"));
    }

    #[test]
    fn small_files_are_not_compressed() {
        // Under the 64-byte floor: identity only, no Vary.
        let c = make_cached("/a.css", "text/css", b"body{}", &pol());
        assert!(c.gzip.is_none() && c.br.is_none());
        assert!(!c.vary);
    }

    #[test]
    fn compressible_content_gets_both_encodings() {
        let data = "body { color: red; }\n".repeat(40); // ~840 bytes, compressible
        let c = make_cached("/big.css", "text/css", data.as_bytes(), &pol());
        assert!(c.gzip.is_some(), "expected gzip variant");
        assert!(c.br.is_some(), "expected brotli variant");
        assert!(c.vary);
        // Compressed forms are actually smaller than identity.
        assert!(c.gzip.as_ref().unwrap().full_ka.len() < c.identity.full_ka.len());
    }

    #[test]
    fn incompressible_type_stays_identity_only() {
        let data = vec![0xABu8; 1000];
        let c = make_cached("/i.png", "image/png", &data, &pol());
        assert!(c.gzip.is_none() && c.br.is_none() && !c.vary);
    }

    #[test]
    fn fingerprinted_file_is_pinned_immutable() {
        let c = make_cached("/app-deadbeef12.js", "text/javascript", b"console.log(1)", &pol());
        assert!(c.cache_control.contains("immutable"));
    }

    #[test]
    fn build_cache_indexes_files_and_skips_hidden() {
        let dir = TempDir::new();
        dir.write("index.html", b"<h1>home</h1>");
        dir.write("style.css", b"body{color:red}");
        dir.write("sub/page.html", b"<h1>sub</h1>");
        dir.write(".well-known/security.txt", b"Contact: x");
        dir.write(".hidden", b"secret");

        let mut total = 0usize;
        let cache = build_cache(dir.path(), &mut total, &pol()).expect("cache built").map;
        assert!(cache.contains_key("/index.html"));
        assert!(cache.contains_key("/style.css"));
        assert!(cache.contains_key("/sub/page.html"));
        assert!(cache.contains_key("/.well-known/security.txt"));
        assert!(!cache.contains_key("/.hidden"), "dotfiles must be skipped");
        assert!(total > 0);
        // cache_bytes reproduces exactly the accounting build_cache charged.
        assert_eq!(cache_bytes(&cache), total);
    }

    #[test]
    fn build_cache_on_missing_root_is_none() {
        let dir = TempDir::new();
        let missing = dir.path().join("does-not-exist");
        let mut total = 0usize;
        assert!(build_cache(&missing, &mut total, &pol()).is_none());
    }

    #[test]
    fn tree_signature_is_stable_until_the_tree_changes() {
        let dir = TempDir::new();
        dir.write("a.txt", b"one");
        let sig1 = tree_signature(dir.path());
        assert_eq!(sig1, tree_signature(dir.path()), "stable with no change");
        dir.write("b.txt", b"two"); // add a file
        assert_ne!(sig1, tree_signature(dir.path()), "new file must change signature");
    }

    #[test]
    fn file_signature_tracks_content_changes() {
        let dir = TempDir::new();
        let p = dir.path().join("c.conf");
        std::fs::write(&p, b"first").unwrap();
        let ps = p.to_str().unwrap();
        let s1 = file_signature(ps);
        std::fs::write(&p, b"a much longer second version").unwrap(); // size changes
        assert_ne!(s1, file_signature(ps));
    }

    #[cfg(unix)]
    #[test]
    fn build_cache_skips_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        dir.write("real.txt", b"real");
        symlink("/etc/hostname", dir.path().join("link.txt")).unwrap();
        let mut total = 0usize;
        let cache = build_cache(dir.path(), &mut total, &pol()).unwrap().map;
        assert!(cache.contains_key("/real.txt"));
        assert!(!cache.contains_key("/link.txt"), "symlinks must never be followed");
    }
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::config::{Config, SiteConfig};
    use crate::testutil::TempDir;

    fn cfg(sites: Vec<SiteConfig>) -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: "443".into(),
            http_host: String::new(),
            http_port: String::new(),
            sites,
            headers: Default::default(),
            max_conns_per_ip: 64,
            max_response_secs: 0,
            storage: crate::config::Storage::Memory,
            disk_cache: None,
        }
    }

    fn site(host: &str, root: Option<&str>, cert: &str, key: &str) -> SiteConfig {
        SiteConfig {
            hosts: vec![host.into()],
            root: root.map(Into::into),
            cert: cert.into(),
            key: key.into(),
            force_ssl: false,
            canonical_urls: false,
            redirects: Default::default(),
            tuning: Tuning::default(),
            headers: Default::default(),
        }
    }

    #[test]
    fn tls_paths_lists_cert_and_key_for_every_site_in_order() {
        // Including the rootless (redirect-only) ones: they terminate TLS too,
        // so their material has to be watched for renewal like any other.
        let c = cfg(vec![
            site("a", Some("/wa"), "ca", "ka"),
            site("b", Some("/wb"), "cb", "kb"),
            site("w", None, "cr", "kr"),
        ]);
        assert_eq!(tls_paths(&c), vec!["ca", "ka", "cb", "kb", "cr", "kr"]);
    }

    #[test]
    fn sample_skips_a_site_that_has_no_tree() {
        // A redirect-only site has no root, so there is nothing to hash, and
        // nothing for the watcher to try (and fail) to rebuild every tick.
        let c = cfg(vec![site("w", None, "cr", "kr")]);
        assert!(sample("/nonexistent.conf", &c).trees.is_empty());
    }

    #[test]
    fn tls_signature_is_order_sensitive_and_does_not_cancel() {
        let dir = TempDir::new();
        dir.write("a", b"one");
        dir.write("b", b"a longer file");
        let a = dir.path().join("a").to_str().unwrap().to_string();
        let b = dir.path().join("b").to_str().unwrap().to_string();

        // The same file twice must not cancel to the empty signature (folded in
        // order with a multiply, not XORed).
        assert_ne!(tls_signature(std::slice::from_ref(&a)), tls_signature(&[a.clone(), a.clone()]));
        // Order of distinct files matters.
        assert_ne!(
            tls_signature(&[a.clone(), b.clone()]),
            tls_signature(&[b.clone(), a.clone()])
        );
        // Stable for the same input.
        assert_eq!(tls_signature(&[a.clone(), b.clone()]), tls_signature(&[a, b]));
    }

    #[test]
    fn sample_captures_config_tls_and_tree_signatures() {
        let dir = TempDir::new();
        let root = dir.path().join("www");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), b"x").unwrap();
        let cert = dir.path().join("c.pem");
        let key = dir.path().join("k.pem");
        std::fs::write(&cert, b"cert-bytes").unwrap();
        std::fs::write(&key, b"key-bytes").unwrap();
        let cfg_path = dir.path().join("server.conf");
        std::fs::write(&cfg_path, b"listen = x:1\n").unwrap();

        let c = cfg(vec![site(
            "localhost",
            Some(root.to_str().unwrap()),
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
        )]);
        let s = sample(cfg_path.to_str().unwrap(), &c);

        // The config file's own signature is captured (this is what stops a
        // boot-time edit from being silently swallowed).
        assert_eq!(s.config, file_signature(cfg_path.to_str().unwrap()));
        assert_eq!(s.tls_files, tls_paths(&c));
        assert_eq!(s.tls, tls_signature(&s.tls_files));
        // Trees are keyed by the canonical root.
        let canon = std::fs::canonicalize(&root).unwrap().display().to_string();
        assert_eq!(s.trees.get(&canon), Some(&tree_signature(&root)));
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::testutil::TempDir;

    fn with(f: impl FnOnce(&mut Tuning)) -> Policy {
        let mut t = Tuning::default();
        f(&mut t);
        Policy::new(t)
    }
    fn css(n: usize) -> Vec<u8> {
        "body { color: red; }\n".repeat(n).into_bytes()
    }

    #[test]
    fn compression_off_stores_identity_only() {
        let p = with(|t| t.compression = false);
        let c = make_cached("/a.css", "text/css", &css(40), &p);
        assert!(c.gzip.is_none() && c.br.is_none(), "compression=off must skip both");
        assert!(!c.vary, "no Vary when there is nothing to negotiate");
    }

    #[test]
    fn min_compress_bytes_gates_small_files() {
        let data = css(1); // 21 bytes
        // Default floor (64) leaves it uncompressed...
        let c = make_cached("/a.css", "text/css", &data, &Policy::new(Tuning::default()));
        assert!(c.gzip.is_none() && c.br.is_none());
        // ...lowering the floor compresses it (gzip of 21B may not be smaller,
        // so assert on the gate being crossed via a larger-but-still-small file).
        let bigger = css(6); // 126 bytes, over a raised floor of 100
        let p = with(|t| t.min_compress_bytes = 100);
        let c2 = make_cached("/a.css", "text/css", &bigger, &p);
        assert!(c2.gzip.is_some() || c2.br.is_some(), "above the floor it should compress");
        let p3 = with(|t| t.min_compress_bytes = 1000);
        let c3 = make_cached("/a.css", "text/css", &bigger, &p3);
        assert!(c3.gzip.is_none() && c3.br.is_none(), "below a raised floor: identity only");
    }

    #[test]
    fn per_encoding_size_ceilings_are_independent() {
        let data = css(40); // ~840 bytes
        // Brotli disabled by ceiling, gzip still applies.
        let p = with(|t| t.max_brotli_bytes = 0);
        let c = make_cached("/a.css", "text/css", &data, &p);
        assert!(c.br.is_none() && c.gzip.is_some(), "only brotli should be suppressed");
        // ...and the reverse.
        let p2 = with(|t| t.max_gzip_bytes = 0);
        let c2 = make_cached("/a.css", "text/css", &data, &p2);
        assert!(c2.gzip.is_none() && c2.br.is_some(), "only gzip should be suppressed");
    }

    #[test]
    fn brotli_quality_changes_the_output() {
        let data = css(200);
        let lo = brotli_compress(&data, 1);
        let hi = brotli_compress(&data, 11);
        assert!(hi.len() <= lo.len(), "q11 should be no larger than q1");
        assert_ne!(lo, hi, "quality must actually reach the encoder");
    }

    #[test]
    fn gzip_level_changes_the_output() {
        let data = css(200);
        let lo = gzip_compress(&data, 1);
        let hi = gzip_compress(&data, 9);
        assert!(hi.len() <= lo.len(), "level 9 should be no larger than level 1");
    }

    #[test]
    fn cache_control_max_ages_are_configurable() {
        let p = with(|t| {
            t.cache_max_age = 300;
            t.immutable_max_age = 604_800;
        });
        let plain = make_cached("/style.css", "text/css", b"x", &p);
        assert_eq!(&*plain.cache_control, "public, max-age=300, must-revalidate");
        let hashed = make_cached("/app-deadbeef12.js", "text/javascript", b"x", &p);
        assert_eq!(&*hashed.cache_control, "public, max-age=604800, immutable");
    }

    #[test]
    fn max_file_size_skips_oversized_files() {
        let dir = TempDir::new();
        dir.write("small.txt", b"tiny");
        dir.write("big.txt", &vec![b'x'; 5000]);
        let p = with(|t| t.max_file_size = 1000);
        let mut total = 0usize;
        let cache = build_cache(dir.path(), &mut total, &p).unwrap().map;
        assert!(cache.contains_key("/small.txt"));
        assert!(!cache.contains_key("/big.txt"), "over max_file_size must be skipped");
    }

    #[test]
    fn max_total_bytes_aborts_the_build() {
        let dir = TempDir::new();
        for i in 0..10 {
            dir.write(&format!("f{i}.txt"), &vec![b'x'; 2000]);
        }
        let p = with(|t| t.max_total_bytes = 4000);
        let mut total = 0usize;
        assert!(
            build_cache(dir.path(), &mut total, &p).is_none(),
            "exceeding max_total_bytes must abort the build, not truncate the cache"
        );
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use crate::testutil::TempDir;

    fn disk_policy(cache_dir: &Path) -> Policy {
        Policy::with_headers(
            Tuning::default(),
            &HeaderConfig::default(),
            Storage::Disk,
            cache_dir.to_path_buf(),
        )
    }

    #[test]
    fn precompressed_sidecars_do_not_collide_with_generated_ones() {
        // A docroot that ships `style.css` alongside a real `style.css.gz`. The
        // normal output of a gzip_static-style build. Both used to snapshot to
        // "<build>/style.css.gz", so one silently overwrote the other and its
        // entry then declared a Content-Length the file on disk did not have.
        let root = TempDir::new();
        let css = "body { color: red; }\n".repeat(40);
        root.write("style.css", css.as_bytes());
        root.write("style.css.gz", b"NOT-REALLY-GZIP");
        let cachedir = TempDir::new();
        let sc = build_cache(root.path(), &mut 0usize, &disk_policy(cachedir.path())).unwrap();

        let css_entry = match sc.map.get("/style.css").unwrap() {
            Cached::Disk(d) => d,
            Cached::Mem(_) => unreachable!(),
        };
        let side_entry = match sc.map.get("/style.css.gz").unwrap() {
            Cached::Disk(d) => d,
            Cached::Mem(_) => unreachable!(),
        };
        let gz = css_entry.gzip.as_ref().expect("css is compressible");
        assert_ne!(gz.path, side_entry.identity.path, "distinct URLs, distinct files");

        // Every variant's declared length must match the bytes actually on disk,
        // or the response under-delivers Content-Length on a live connection.
        for (label, path, len) in [
            ("/style.css identity", &css_entry.identity.path, css_entry.identity.len),
            ("/style.css gzip", &gz.path, gz.len),
            ("/style.css.gz identity", &side_entry.identity.path, side_entry.identity.len),
        ] {
            let on_disk = fs::metadata(path).unwrap().len();
            assert_eq!(on_disk, len, "{label}: declared {len}, on disk {on_disk}");
        }
        // And the sidecar still holds its own bytes, not the generated gzip.
        assert_eq!(fs::read(&side_entry.identity.path).unwrap(), b"NOT-REALLY-GZIP");
    }

    #[test]
    fn an_unreadable_subdirectory_fails_the_build_instead_of_truncating_it() {
        use std::os::unix::fs::PermissionsExt;
        let root = TempDir::new();
        root.write("index.html", b"<h1>home</h1>");
        let locked = root.path().join("private");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join("secret.html"), b"x").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        let built = build_cache(root.path(), &mut 0usize, &Policy::new(Tuning::default()));
        // Restore before asserting so the TempDir can always clean itself up.
        let _ = fs::set_permissions(&locked, fs::Permissions::from_mode(0o755));
        assert!(
            built.is_none(),
            "a subtree the process cannot read must fail the build, not yield a \
             cache that silently 404s everything under it"
        );
    }

    #[test]
    fn disk_build_snapshots_bodies_and_keeps_only_headers_in_ram() {
        let root = TempDir::new();
        root.write("index.html", b"<h1>home</h1>");
        // A big body so the bodies-excluded RAM saving dominates the fixed
        // per-variant header cost.
        let css = "body { color: red; }\n".repeat(4000); // ~84 KB, compressible
        root.write("style.css", css.as_bytes());
        let cachedir = TempDir::new();
        let mut disk_total = 0usize;
        let sc = build_cache(root.path(), &mut disk_total, &disk_policy(cachedir.path())).expect("built");

        let e = match sc.map.get("/style.css").expect("style cached") {
            Cached::Disk(d) => d,
            Cached::Mem(_) => panic!("disk storage expected"),
        };
        // Identity plus gzip and brotli sidecars are all real files on disk.
        assert!(e.identity.path.is_file());
        assert!(e.gzip.as_ref().unwrap().path.is_file());
        assert!(e.br.as_ref().unwrap().path.is_file());
        // The identity length matches the source and the header advertises it.
        assert_eq!(e.identity.len, css.len() as u64);
        let hdr = String::from_utf8(e.identity.header_ka.clone()).unwrap();
        assert!(hdr.contains(&format!("Content-Length: {}", css.len())), "{hdr}");
        assert!(hdr.contains("Vary: Accept-Encoding"), "{hdr}");
        assert!(hdr.ends_with("\r\n\r\n"));
        // Accounting counts exactly the retained headers...
        assert_eq!(cache_bytes(&sc.map), disk_total);
        // ...and holds no bodies in RAM: the same tree in Memory mode charges the
        // bodies too, so disk RAM is a fraction of memory RAM.
        let mut mem_total = 0usize;
        build_cache(root.path(), &mut mem_total, &Policy::new(Tuning::default())).unwrap();
        assert!(
            disk_total * 4 < mem_total,
            "disk RAM ({disk_total}) must be far below memory RAM ({mem_total})"
        );
    }

    #[test]
    fn dropping_the_cache_removes_the_snapshot_dir() {
        let root = TempDir::new();
        root.write("a.txt", b"hello");
        let cachedir = TempDir::new();
        let mut total = 0usize;
        let sc = build_cache(root.path(), &mut total, &disk_policy(cachedir.path())).unwrap();
        let snapshot = sc._build_dir.as_ref().unwrap().0.clone();
        assert!(snapshot.is_dir(), "snapshot dir exists while the cache is live");
        drop(sc);
        assert!(!snapshot.exists(), "BuildDir drop must remove the snapshot");
    }

    #[test]
    fn disk_and_memory_headers_are_byte_identical() {
        // Same file, same policy but different backends -> identical headers
        // (Content-Length, ETag, Vary, Cache-Control, security headers).
        let data = "body { color: red; }\n".repeat(20);
        let cachedir = TempDir::new();
        let dp = disk_policy(cachedir.path());
        let root = TempDir::new();
        root.write("style.css", data.as_bytes());
        let sc = build_cache(root.path(), &mut 0, &dp).unwrap();
        let disk = match sc.map.get("/style.css").unwrap() {
            Cached::Disk(d) => d,
            Cached::Mem(_) => unreachable!(),
        };
        let mem = make_cached("/style.css", "text/css; charset=utf-8", data.as_bytes(), &Policy::new(Tuning::default()));
        assert_eq!(disk.identity.header_ka, mem.identity.full_ka[..mem.identity.header_len]);
        assert_eq!(disk.identity.etag, mem.identity.etag);
    }
}
