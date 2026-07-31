//! Config file parsing. Kept free of I/O beyond `load_config` so the parser
//! itself is a pure `&str -> Result<Config, String>` that is trivial to test.
//!
//! The format is line-based. Bare `key = value` lines at the top level are
//! server-wide; a `site <host[, host2]> { ... }` block describes one virtual
//! host and may override most of them for itself:
//!
//! ```text
//! listen = [::]:443
//! csp = default-src 'self'          # default for every site
//!
//! site example.com, www.example.com {
//!     root = /var/www/example
//!     cert = /etc/bare-server/tls/example/cert.pem
//!     key  = /etc/bare-server/tls/example/key.pem
//!     csp  = default-src 'self'; img-src *   # overrides the default above
//!
//!     redirect /old    -> /new
//!     redirect /docs/* -> /help/$1
//! }
//! ```
//!
//! Three key classes, enforced so a directive in the wrong place is an error
//! rather than a silent no-op: server-only (`listen`, `storage`, the shared
//! cache budget, the connection caps), site-only (`root`, `cert`, `key`,
//! `force_ssl`, `redirect`), and the rest, settable at either level, where the
//! server-level value is the default and a site block overrides it.

use std::collections::HashMap;
use std::fs;

// ------------------------------------------------------------ redirect rules

/// One site's path redirect rules, indexed for matching at request time.
///
/// Every redirect this server emits is a `301 Moved Permanently`; the status is
/// not configurable, so a rule is just a pattern and a target. Matching is
/// deliberately not a regex: an exact-path hash lookup, then a longest-first
/// scan of the prefix rules, then the optional whole-host catch-all. Per-request
/// cost is O(1) plus a scan bounded by the number of prefix rules the operator
/// wrote, and no pattern the format can express makes that worse. That is the
/// whole point in a server whose hot path is otherwise one hash lookup and one
/// `write_all`.
#[derive(Clone, Default)]
pub(crate) struct Redirects {
    /// Whole-path equality: `redirect /old -> /new`.
    exact: HashMap<String, String>,
    /// `redirect /docs/* -> /help/$1`, stored as the literal prefix (`/docs/`).
    /// Sorted longest-first by `finish`, so the most specific rule wins whatever
    /// order the file happens to list them in.
    prefix: Vec<(String, String)>,
    /// `redirect * -> https://example.com$0`: anything not matched above.
    all: Option<String>,
}

/// Expand a target template against one match. `$0` is the whole request path,
/// `$1` the part a `/prefix/*` pattern captured, `$$` a literal `$`. Anything
/// else after a `$` is left alone: targets are ordinary URLs and a lone `$` in
/// one should not have to be escaped.
fn expand(template: &str, path: &str, cap: &str) -> String {
    if !template.contains('$') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len() + path.len());
    let mut it = template.chars().peekable();
    while let Some(c) = it.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match it.peek() {
            Some('0') => {
                out.push_str(path);
                it.next();
            }
            Some('1') => {
                out.push_str(cap);
                it.next();
            }
            Some('$') => {
                out.push('$');
                it.next();
            }
            _ => out.push('$'),
        }
    }
    out
}

/// Would this rule send a matching request straight back to the path it came
/// from? Answered by *expanding* the target against a representative match
/// rather than by comparing spellings, because the same loop has several: `/a ->
/// /a` is obvious, but `/a -> $0` and `/docs/* -> $0` expand to exactly the same
/// thing and a textual check waves them through.
///
/// The query and fragment are dropped before comparing. Neither reaches the
/// server on the next hop in a way that changes which rule matches: a fragment
/// is never sent at all, and rules match on the path with the query stripped,
/// so `/a -> $0#x` and `/a -> $0?v=1` both loop just as surely as `/a -> $0`.
///
/// A target that is an absolute URL is left alone: it names some other origin,
/// and this server cannot know whether that one loops back.
fn loops_forever(target: &str, probe_path: &str, capture: &str) -> bool {
    if target.starts_with("http://") || target.starts_with("https://") {
        return false;
    }
    let expanded = expand(target, probe_path, capture);
    let bare = expanded.split(['?', '#']).next().unwrap_or("");
    bare == probe_path
}

impl Redirects {
    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.prefix.is_empty() && self.all.is_none()
    }

    /// Resolve one request path to a redirect target, or `None` to keep serving
    /// normally. `path` is the RAW request path, still percent-encoded with the
    /// query already stripped, so a rule matches the bytes the client actually sent
    /// and the capture it hands back keeps whatever encoding was there. The
    /// caller re-attaches the query string and, for a target that is a bare path,
    /// the scheme and authority.
    pub(crate) fn resolve(&self, path: &str) -> Option<String> {
        if let Some(t) = self.exact.get(path) {
            return Some(expand(t, path, ""));
        }
        for (p, t) in &self.prefix {
            if let Some(rest) = path.strip_prefix(p.as_str()) {
                return Some(expand(t, path, rest));
            }
        }
        // The catch-all captures the whole path as `$1` as well as `$0`: with an
        // empty prefix the "remainder" simply is the whole path.
        self.all.as_ref().map(|t| expand(t, path, path))
    }

    /// Record one `redirect <pattern> -> <target>` rule. Every rejection here is
    /// a config that would misbehave at runtime: an ambiguous duplicate, a
    /// target that cannot go in a `Location`, or a rule that redirects a path to
    /// itself. This server would rather fail the (re)load than serve it.
    fn push(&mut self, pattern: &str, target: &str) -> Result<(), String> {
        // The target is interpolated into a response header, and `$0`/`$1` splice
        // in request bytes at serve time, but those are control-character-free
        // by the time they get there (the request target is validated up front),
        // so checking the template alone covers both halves.
        if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err("redirect: control characters are not allowed in a target".into());
        }
        if target.is_empty() {
            return Err("redirect: empty target".into());
        }
        // Either an absolute URL (cross-host) or a rooted path on this host.
        // Anything else, such as a bare "example.com" or a relative "new", would produce
        // a Location the client resolves somewhere unintended. A leading `$0` is
        // rooted too: it expands to the request path, which always starts with
        // '/'. A leading `$1` is not: a `/docs/*` remainder is "a/b", so
        // `-> $1` would emit a relative Location.
        let absolute = target.starts_with("http://") || target.starts_with("https://");
        if !absolute && !target.starts_with('/') && !target.starts_with("$0") {
            return Err(format!(
                "redirect: target must be an absolute http(s):// URL, a path starting with '/', or $0 (got: {target})"
            ));
        }
        // `$2` and up never have a value: there is exactly one capture.
        let mut it = target.chars().peekable();
        while let Some(c) = it.next() {
            if c != '$' {
                continue;
            }
            match it.peek() {
                Some('$') | Some('0') | Some('1') => {
                    it.next();
                }
                Some(d) if d.is_ascii_digit() => {
                    return Err(format!(
                        "redirect: unknown capture ${d} in target (only $0, the whole path, and $1, a /prefix/* remainder, exist)"
                    ));
                }
                _ => {}
            }
        }

        if pattern == "*" {
            // `* -> $0` (or `$1`) redirects every path to itself, forever.
            if loops_forever(target, "/probe", "/probe") {
                return Err("redirect: '* -> $0' redirects every path to itself".into());
            }
            if self.all.is_some() {
                return Err("redirect: duplicate '*' rule (a site has at most one catch-all)".into());
            }
            self.all = Some(target.to_string());
            return Ok(());
        }
        if !pattern.starts_with('/') {
            return Err(format!(
                "redirect: pattern must be a path starting with '/', or '*' for the whole host (got: {pattern})"
            ));
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            // Only `/some/prefix/*`. A `*` mid-pattern would need a matcher this
            // deliberately does not have, and a `*` not on a segment boundary
            // (`/a*`) reads as if it also matched `/abc`, which it would. Anchor
            // it to the slash so the meaning is never ambiguous.
            if prefix.contains('*') || !prefix.ends_with('/') {
                return Err(format!("redirect: '*' is only allowed as a trailing /prefix/* (got: {pattern})"));
            }
            let probe = format!("{prefix}probe");
            if loops_forever(target, &probe, "probe") {
                return Err(format!("redirect: '{pattern}' redirects every matching path to itself"));
            }
            if self.prefix.iter().any(|(p, _)| p == prefix) {
                return Err(format!("redirect: duplicate pattern: {pattern}"));
            }
            self.prefix.push((prefix.to_string(), target.to_string()));
            return Ok(());
        }
        if pattern.contains('*') {
            return Err(format!("redirect: '*' is only allowed as a trailing /prefix/* (got: {pattern})"));
        }
        if loops_forever(target, pattern, "") {
            return Err(format!("redirect: '{pattern}' redirects to itself"));
        }
        // `$1` is the /prefix/* capture; on an exact rule it is always empty, so
        // it is a mistake rather than a no-op worth silently allowing.
        if target.contains("$1") {
            return Err(format!("redirect: $1 has no value in the exact rule '{pattern}' (use $0 for the whole path)"));
        }
        if self.exact.insert(pattern.to_string(), target.to_string()).is_some() {
            return Err(format!("redirect: duplicate pattern: {pattern}"));
        }
        Ok(())
    }

    /// Longest prefix first, so `/docs/api/*` beats `/docs/*` no matter which
    /// line came first. Called once per site after its block is parsed.
    fn finish(&mut self) {
        self.prefix.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
    }
}

// ------------------------------------------------------------------- config

/// One virtual host: its domain name(s), optional document root, TLS cert/key
/// (used for SNI selection), redirect rules, and its own resolved copy of every
/// per-site tunable.
///
/// `hosts` may list several comma-separated names. They share one cache, one
/// rule set and one certificate, which must cover every name listed.
pub(crate) struct SiteConfig {
    pub(crate) hosts: Vec<String>,
    /// Document root, or `None` for a host that only issues redirects (www ->
    /// apex). Such a host still terminates TLS, so it still needs a cert: the
    /// handshake has to complete before the redirect can be sent.
    pub(crate) root: Option<String>,
    pub(crate) cert: String,
    pub(crate) key: String,
    /// Redirect this site's plain-HTTP traffic to HTTPS instead of serving it.
    /// ON by default: the :80 listener answers every request for this host with
    /// a 301 to the https:// form. `force_ssl = off` turns it off so content is
    /// served over :80 too. The ACME http-01 prefix stays reachable over plain
    /// HTTP either way, or renewal breaks.
    pub(crate) force_ssl: bool,
    /// Redirect the `.html` spellings of a URL to the canonical directory form
    /// (`/about.html` and `/about/index.html` -> `/about/`, `/index.html` ->
    /// `/`). OFF by default: it changes what a URL does, so it is opt-in per
    /// site. See `canonical_form`.
    pub(crate) canonical_urls: bool,
    pub(crate) redirects: Redirects,
    /// Cache/compression settings for this site: the server-level values with
    /// this block's overrides applied.
    pub(crate) tuning: Tuning,
    /// Response headers for this site, same inheritance.
    pub(crate) headers: HeaderConfig,
}

pub(crate) struct Config {
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) http_host: String, // optional plain-HTTP listener (empty = disabled)
    pub(crate) http_port: String,
    pub(crate) sites: Vec<SiteConfig>,
    /// Server-level response headers. Every site carries its own resolved copy
    /// of these; this one covers the responses sent before a host is known: a
    /// 400 on a malformed request head, a 404 for an unconfigured Host, which
    /// belong to no site.
    ///
    /// There is deliberately no server-level `Tuning` here: the cache and
    /// compression settings only ever act through a site, so each site's
    /// resolved copy (defaults + its own overrides) is the single source of
    /// truth, including `max_total_bytes`, which is copied unchanged into every
    /// site precisely because it is one shared budget.
    pub(crate) headers: HeaderConfig,
    /// Max concurrent connections from one source IP (0 = unlimited). A single
    /// peer cannot hold more than this many slots, so it cannot exhaust the
    /// global cap on its own. Applied per listener.
    pub(crate) max_conns_per_ip: usize,
    /// Absolute wall-clock cap (seconds) on a single in-flight response body,
    /// enforced at the socket below rustls (0 = disabled). This is deliberately
    /// off by default: unlike the no-progress deadline it *will* truncate a
    /// legitimately slow large download, so it is a knob for hosts that serve
    /// only small files and want a hard bound on slow-read slot pinning.
    pub(crate) max_response_secs: u64,
    /// Where site content lives at runtime. `Memory` (default) loads every file
    /// into RAM at boot as precomputed responses. `Disk` holds only a small
    /// index in RAM and streams bodies (and precompressed sidecars) from
    /// `disk_cache`, letting the OS page cache do the buffering.
    pub(crate) storage: Storage,
    /// Directory for the on-disk content snapshot in `Disk` mode. Required when
    /// `storage = disk`; ignored in memory mode. Must be on real disk (not a
    /// tmpfs, which would defeat the purpose) and writable by the server.
    pub(crate) disk_cache: Option<String>,
}

/// Runtime storage backend for site content.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Storage {
    /// Everything precomputed and held in RAM (the original design).
    Memory,
    /// Index in RAM; bodies + sidecars snapshotted to disk and streamed.
    Disk,
}

/// Response-header policy: the security headers sent on every response. Kept
/// out of `Tuning` (which is `Copy` and threaded by value through the cache
/// build) because `csp` is an owned string.
#[derive(Clone)]
pub(crate) struct HeaderConfig {
    pub(crate) hsts_max_age: u64, // 0 disables the Strict-Transport-Security header
    pub(crate) hsts_include_subdomains: bool,
    pub(crate) hsts_preload: bool,
    pub(crate) csp: String, // empty = no Content-Security-Policy header
}

impl Default for HeaderConfig {
    fn default() -> Self {
        HeaderConfig {
            hsts_max_age: DEF_HSTS_MAX_AGE,
            hsts_include_subdomains: true,
            hsts_preload: true,
            csp: String::new(),
        }
    }
}

impl HeaderConfig {
    /// Render the security-header block appended to every response: the four
    /// fixed headers, plus HSTS (unless disabled with `hsts_max_age = 0`) and
    /// CSP (only when configured). Each line ends with CRLF; the caller adds the
    /// blank-line terminator.
    pub(crate) fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("X-Content-Type-Options: nosniff\r\n");
        s.push_str("X-Frame-Options: SAMEORIGIN\r\n");
        s.push_str("Referrer-Policy: strict-origin-when-cross-origin\r\n");
        s.push_str("Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n");
        if self.hsts_max_age > 0 {
            s.push_str("Strict-Transport-Security: max-age=");
            s.push_str(&self.hsts_max_age.to_string());
            if self.hsts_include_subdomains {
                s.push_str("; includeSubDomains");
            }
            if self.hsts_preload {
                s.push_str("; preload");
            }
            s.push_str("\r\n");
        }
        if !self.csp.is_empty() {
            s.push_str("Content-Security-Policy: ");
            s.push_str(&self.csp);
            s.push_str("\r\n");
        }
        s
    }
}

// ---- defaults for the cache/compression tunables ----

pub(crate) const DEF_MAX_FILE_SIZE: usize = 256 << 20; // skip any single file > 256 MiB
// Refuse to cache past 2 GiB, counted across every site and against the bytes
// actually retained (each of identity/gzip/br is its own buffer). Note a reload
// builds the replacement cache before dropping the old one, so both are
// resident at peak: size the host for 2x this ceiling.
pub(crate) const DEF_MAX_TOTAL_BYTES: usize = 2 << 30;
// Above this, a file gets no brotli variant. Brotli is done at boot, serially,
// at quality 11 (~1 MB/s), and nothing is bound until it finishes, so a 60 MB
// wasm bundle or a 120 MB json blob would turn every start into a multi-minute
// connection-refused window. Browsers handle a br-less response fine (they fall
// back to gzip or identity); an unreachable port they do not.
pub(crate) const DEF_MAX_BROTLI_BYTES: usize = 8 << 20;
// gzip (miniz_oxide) runs at tens of MB/s, ~20-50x brotli q11, so it earns a
// much higher ceiling: halving a large minified bundle on the wire is well
// worth the sub-second boot cost. Only past this, where even gzip's boot cost
// would stall startup, is a file cached identity-only.
pub(crate) const DEF_MAX_GZIP_BYTES: usize = 64 << 20;
// Below this a file is stored identity-only: the headers alone outweigh any
// saving, and a compressed form is often larger than the source.
pub(crate) const DEF_MIN_COMPRESS_BYTES: usize = 64;
pub(crate) const DEF_BROTLI_QUALITY: u32 = 11; // max; the boot-cost knob
pub(crate) const DEF_GZIP_LEVEL: u32 = 9; // flate2 "best"
// Un-fingerprinted URLs revalidate rather than pin: the bytes behind them can
// change without the URL changing, so a non-zero max-age strands stale content.
pub(crate) const DEF_CACHE_MAX_AGE: u64 = 0;
// A fingerprinted URL names one exact set of bytes, so it is safe to pin for a
// year and mark immutable.
pub(crate) const DEF_IMMUTABLE_MAX_AGE: u64 = 31_536_000;
// HSTS: two years, the value the header carried when it was a compile-time
// constant. 0 disables the header entirely.
pub(crate) const DEF_HSTS_MAX_AGE: u64 = 63_072_000;
// Per-source-IP concurrent-connection cap. Browsers open ~6 connections per
// host, so this leaves ample room for real clients while stopping one peer from
// taking the whole global cap. 0 disables it (e.g. behind a shared-IP proxy).
pub(crate) const DEF_MAX_CONNS_PER_IP: usize = 64;

/// Cache and compression settings. Given at the top level they are the default
/// for every site; a `site` block may override any of them for itself, except
/// `max_total_bytes`, which is one budget shared across every site and so is
/// accepted at the top level only.
///
/// Every field has a default, so a config that sets none of them is valid. All
/// primitives, so `Copy`: it is threaded through the cache build by value.
#[derive(Clone, Copy)]
pub(crate) struct Tuning {
    pub(crate) compression: bool,
    pub(crate) brotli_quality: u32,
    pub(crate) gzip_level: u32,
    pub(crate) min_compress_bytes: usize,
    pub(crate) max_brotli_bytes: usize,
    pub(crate) max_gzip_bytes: usize,
    pub(crate) max_file_size: usize,
    pub(crate) max_total_bytes: usize,
    pub(crate) cache_max_age: u64,
    pub(crate) immutable_max_age: u64,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            compression: true,
            brotli_quality: DEF_BROTLI_QUALITY,
            gzip_level: DEF_GZIP_LEVEL,
            min_compress_bytes: DEF_MIN_COMPRESS_BYTES,
            max_brotli_bytes: DEF_MAX_BROTLI_BYTES,
            max_gzip_bytes: DEF_MAX_GZIP_BYTES,
            max_file_size: DEF_MAX_FILE_SIZE,
            max_total_bytes: DEF_MAX_TOTAL_BYTES,
            cache_max_age: DEF_CACHE_MAX_AGE,
            immutable_max_age: DEF_IMMUTABLE_MAX_AGE,
        }
    }
}

// -------------------------------------------------------------- value parsers

/// A byte size: a plain count, or one with a K/M/G suffix (binary, so 1K = 1024).
fn parse_size(key: &str, v: &str) -> Result<usize, String> {
    let v = v.trim();
    let (digits, mult) = match v.as_bytes().last() {
        Some(c) if c.eq_ignore_ascii_case(&b'k') => (&v[..v.len() - 1], 1usize << 10),
        Some(c) if c.eq_ignore_ascii_case(&b'm') => (&v[..v.len() - 1], 1usize << 20),
        Some(c) if c.eq_ignore_ascii_case(&b'g') => (&v[..v.len() - 1], 1usize << 30),
        _ => (v, 1usize),
    };
    let n: usize = digits
        .trim()
        .parse()
        .map_err(|_| format!("{key}: expected a byte size like 8M or 1048576 (got: {v})"))?;
    n.checked_mul(mult).ok_or_else(|| format!("{key}: size overflows (got: {v})"))
}

fn parse_bool(key: &str, v: &str) -> Result<bool, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err(format!("{key}: expected on/off (got: {v})")),
    }
}

fn parse_ranged(key: &str, v: &str, lo: u32, hi: u32) -> Result<u32, String> {
    let n: u32 = v
        .trim()
        .parse()
        .map_err(|_| format!("{key}: expected a number {lo}-{hi} (got: {v})"))?;
    if n < lo || n > hi {
        return Err(format!("{key}: must be {lo}-{hi} (got: {n})"));
    }
    Ok(n)
}

/// A duration in seconds. Unbounded, because most callers are `max-age` header
/// values where a year is perfectly ordinary; see `parse_deadline_secs` for the
/// ones that become an `Instant`.
fn parse_secs(key: &str, v: &str) -> Result<u64, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("{key}: expected a number of seconds (got: {v})"))
}

/// A duration that will be added to an `Instant`, so it has to be bounded:
/// `Instant + Duration` panics on overflow, and `DeadlineIo` builds one per
/// connection, and an unchecked value would panic every worker thread while the
/// process kept reporting healthy. A day is far past any useful response
/// deadline, so anything beyond it is a typo worth failing the load over.
fn parse_deadline_secs(key: &str, v: &str) -> Result<u64, String> {
    const MAX_SECS: u64 = 86_400;
    let n = parse_secs(key, v)?;
    if n > MAX_SECS {
        return Err(format!("{key}: at most {MAX_SECS} seconds (one day), got {n}"));
    }
    Ok(n)
}

fn parse_count(key: &str, v: &str) -> Result<usize, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("{key}: expected a non-negative integer (got: {v})"))
}

/// A value destined for a response header. The config file is trusted, but a
/// stray control byte here would inject into (or truncate) the header block, so
/// reject CR, LF, and every other control character defensively.
fn parse_header_value(key: &str, v: &str) -> Result<String, String> {
    let v = v.trim();
    if v.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("{key}: control characters are not allowed in a header value"));
    }
    Ok(v.to_string())
}

// ------------------------------------------------------------------ parsing

/// Settings valid both at the top level (as the default for every site) and
/// inside a `site` block (as that site's override). Returns `false` for a key it
/// does not own, so each caller can report the right error for its context.
fn apply_shared(t: &mut Tuning, h: &mut HeaderConfig, k: &str, v: &str) -> Result<bool, String> {
    match k {
        // ---- cache / compression ----
        "compression" => t.compression = parse_bool(k, v)?,
        "brotli_quality" => t.brotli_quality = parse_ranged(k, v, 0, 11)?,
        "gzip_level" => t.gzip_level = parse_ranged(k, v, 0, 9)?,
        "min_compress_bytes" => t.min_compress_bytes = parse_size(k, v)?,
        "max_brotli_bytes" => t.max_brotli_bytes = parse_size(k, v)?,
        "max_gzip_bytes" => t.max_gzip_bytes = parse_size(k, v)?,
        "max_file_size" => t.max_file_size = parse_size(k, v)?,
        "cache_max_age" => t.cache_max_age = parse_secs(k, v)?,
        "immutable_max_age" => t.immutable_max_age = parse_secs(k, v)?,
        // ---- security response headers ----
        "hsts_max_age" => h.hsts_max_age = parse_secs(k, v)?,
        "hsts_include_subdomains" => h.hsts_include_subdomains = parse_bool(k, v)?,
        "hsts_preload" => h.hsts_preload = parse_bool(k, v)?,
        "csp" => h.csp = parse_header_value(k, v)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Keys that only make sense once for the whole process. Listed so a site block
/// can say *why* they are rejected rather than "unknown key", which would read
/// like a typo.
fn server_only_reason(k: &str) -> Option<&'static str> {
    Some(match k {
        "listen" | "listen_http" => "the listeners are process-wide",
        "max_total_bytes" => "the cache budget is one pool shared by every site",
        "storage" | "disk_cache" => "the storage backend is process-wide",
        "max_conns_per_ip" | "max_response_secs" => {
            "connection limits are enforced per listener, before the Host is known"
        }
        _ => return None,
    })
}

/// The keys a `site` block owns. Used to explain a site-only key found at the
/// top level, which is otherwise indistinguishable from a typo.
fn is_site_only(k: &str) -> bool {
    matches!(k, "root" | "cert" | "key" | "force_ssl" | "canonical_urls" | "redirect")
}

fn at(line_no: usize, msg: impl AsRef<str>) -> String {
    format!("config line {line_no}: {}", msg.as_ref())
}

/// `site` takes a block, not a `=` value. Where the line looks like
/// `site = host root cert key [flag]`, rewrite it into the block that means the
/// same thing: showing the operator their own values converted beats a generic
/// "use a block", which leaves them to work out the mapping by hand.
fn explain_site_line(v: &str) -> String {
    let p: Vec<&str> = v.split_whitespace().collect();
    let mut s = String::from("`site = ...` is not valid: a site is a block");
    if (4..=5).contains(&p.len()) {
        s.push_str(":\n\n");
        s.push_str(&format!("    site {} {{\n", p[0]));
        s.push_str(&format!("        root = {}\n", p[1]));
        s.push_str(&format!("        cert = {}\n", p[2]));
        s.push_str(&format!("        key  = {}\n", p[3]));
        if p.get(4) == Some(&"allow_http") {
            s.push_str("        force_ssl = off\n");
        }
        s.push_str("    }");
    } else {
        s.push_str(". See server.conf.example");
    }
    s
}

/// The same, for a `redirect = from to cert key` line. A redirect-only host is
/// an ordinary site block with no root and one catch-all rule. There is no
/// second kind of vhost in either the config or the server.
fn explain_redirect_line(v: &str) -> String {
    let p: Vec<&str> = v.split_whitespace().collect();
    let mut s = String::from(
        "`redirect = ...` is not valid here: a redirect-only host is a site block with no root",
    );
    if p.len() == 4 {
        s.push_str(":\n\n");
        s.push_str(&format!("    site {} {{\n", p[0]));
        s.push_str(&format!("        cert = {}\n", p[2]));
        s.push_str(&format!("        key  = {}\n", p[3]));
        s.push_str(&format!("        redirect * -> https://{}$0\n", p[1]));
        s.push_str("    }");
    } else {
        s.push_str(". See server.conf.example");
    }
    s
}

/// A site block still being read: the raw values, plus its setting overrides
/// held as `(line, key, value)` so they can be applied *after* the whole file is
/// parsed. Deferring them is what makes the file order-independent: a top-level
/// `csp` written below a site block is still that site's default.
struct PendingSite {
    line: usize,
    hosts: Vec<String>,
    root: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    force_ssl: bool,
    canonical_urls: bool,
    redirects: Redirects,
    overrides: Vec<(usize, String, String)>,
}

/// Parse the config text. Returns Err instead of exiting so a bad *reload*
/// leaves the running server untouched rather than killing it.
pub(crate) fn parse_config(text: &str) -> Result<Config, String> {
    let (mut host, mut port) = (String::new(), String::new());
    let (mut http_host, mut http_port) = (String::new(), String::new());
    let mut pending: Vec<PendingSite> = Vec::new();
    let mut tuning = Tuning::default();
    let mut headers = HeaderConfig::default();
    let mut max_conns_per_ip = DEF_MAX_CONNS_PER_IP;
    let mut max_response_secs: u64 = 0;
    let mut storage = Storage::Memory;
    let mut disk_cache: Option<String> = None;
    // `Some` while inside a `site { ... }` block.
    let mut cur: Option<PendingSite> = None;

    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        // A `#` starts a comment anywhere on the line, so a rule can be annotated
        // in place. Values that legitimately contain `#` (a CSP hash source, a
        // fragment in a redirect target) would be truncated, so only a `#` that
        // starts the line or follows whitespace counts, so `url(#a)` survives.
        let line = match raw.find('#') {
            Some(0) => "",
            Some(p) if raw.as_bytes()[p - 1].is_ascii_whitespace() => &raw[..p],
            _ => raw,
        }
        .trim();
        if line.is_empty() {
            continue;
        }

        // ---- block delimiters ----
        if line == "}" {
            let mut site = cur.take().ok_or_else(|| at(n, "stray '}' outside a site block"))?;
            site.redirects.finish();
            pending.push(site);
            continue;
        }
        if let Some(rest) = line.strip_prefix("site ").or_else(|| line.strip_prefix("site\t")) {
            let rest = rest.trim();
            // The old flat form is a hard error with the block spelled out, not a
            // silent reinterpretation: `site = a.com /w /c /k` would otherwise
            // parse as a host literally named "= a.com".
            if let Some(v) = rest.strip_prefix('=') {
                return Err(at(n, explain_site_line(v.trim())));
            }
            if cur.is_some() {
                return Err(at(n, "site blocks cannot nest"));
            }
            let hosts = rest
                .strip_suffix('{')
                .ok_or_else(|| at(n, "a site must open a block: site <host[, host2]> {"))?;
            let hosts: Vec<String> = hosts
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect();
            if hosts.is_empty() {
                return Err(at(n, "site has no host names"));
            }
            cur = Some(PendingSite {
                line: n,
                hosts,
                root: None,
                cert: None,
                key: None,
                // Secure default: a site that says nothing about HTTP redirects
                // to HTTPS rather than silently serving plaintext.
                force_ssl: true,
                // Off by default: this one changes what a URL does, and the
                // safe direction for that is to keep serving what it served.
                canonical_urls: false,
                redirects: Redirects::default(),
                overrides: Vec::new(),
            });
            continue;
        }

        // ---- redirect rules (site-only, and the one directive with no `=`) ----
        if let Some(rest) = line.strip_prefix("redirect ").or_else(|| line.strip_prefix("redirect\t")) {
            let rest = rest.trim();
            if let Some(v) = rest.strip_prefix('=') {
                return Err(at(n, explain_redirect_line(v.trim())));
            }
            let site = cur
                .as_mut()
                .ok_or_else(|| at(n, "redirect rules belong inside a site block"))?;
            let (pat, target) = rest
                .split_once("->")
                .ok_or_else(|| at(n, "redirect must be: redirect <pattern> -> <target>"))?;
            let (pat, target) = (pat.trim(), target.trim());
            if pat.is_empty() {
                return Err(at(n, "redirect: empty pattern"));
            }
            site.redirects.push(pat, target).map_err(|e| at(n, e))?;
            continue;
        }

        // ---- key = value ----
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| at(n, format!("malformed config line: {line}")))?;
        let (k, v) = (k.trim(), v.trim());

        if let Some(site) = cur.as_mut() {
            match k {
                "root" => site.root = Some(v.to_string()),
                "cert" => site.cert = Some(v.to_string()),
                "key" => site.key = Some(v.to_string()),
                "force_ssl" => site.force_ssl = parse_bool(k, v).map_err(|e| at(n, e))?,
                "canonical_urls" => site.canonical_urls = parse_bool(k, v).map_err(|e| at(n, e))?,
                _ => {
                    if let Some(why) = server_only_reason(k) {
                        return Err(at(n, format!("{k} is a server-level setting ({why})")));
                    }
                    // Validated here so a typo'd value fails at the line that
                    // holds it; the effect is applied once the file's top-level
                    // defaults are known.
                    let (mut t, mut h) = (tuning, headers.clone());
                    if !apply_shared(&mut t, &mut h, k, v).map_err(|e| at(n, e))? {
                        return Err(at(n, format!("unknown site setting: {k}")));
                    }
                    site.overrides.push((n, k.to_string(), v.to_string()));
                }
            }
            continue;
        }

        match k {
            "listen" => {
                // Split on the LAST colon so IPv6 literals survive.
                let (h, p) = v.rsplit_once(':').ok_or_else(|| at(n, "listen must be host:port"))?;
                if h.trim().is_empty() || p.trim().is_empty() {
                    return Err(at(n, "listen must be host:port, e.g. [::]:443"));
                }
                host = h.to_string();
                port = p.to_string();
            }
            "listen_http" => {
                let (h, p) = v
                    .rsplit_once(':')
                    .ok_or_else(|| at(n, "listen_http must be host:port"))?;
                // An empty host is the *disabled* sentinel, reachable only by
                // omitting the key. Accepting `listen_http = :80` here would
                // silently mean "run no HTTP listener": port 80 stops issuing
                // redirects and http-01 renewal breaks, with nothing logged.
                if h.trim().is_empty() || p.trim().is_empty() {
                    return Err(at(n, "listen_http must be host:port, e.g. [::]:80"));
                }
                http_host = h.to_string();
                http_port = p.to_string();
            }
            // ---- server-only ----
            "max_total_bytes" => tuning.max_total_bytes = parse_size(k, v).map_err(|e| at(n, e))?,
            "max_conns_per_ip" => max_conns_per_ip = parse_count(k, v).map_err(|e| at(n, e))?,
            "max_response_secs" => {
                max_response_secs = parse_deadline_secs(k, v).map_err(|e| at(n, e))?
            }
            "storage" => {
                storage = match v.trim().to_ascii_lowercase().as_str() {
                    "memory" | "mem" | "ram" => Storage::Memory,
                    "disk" => Storage::Disk,
                    _ => return Err(at(n, format!("storage: expected memory or disk (got: {v})"))),
                }
            }
            "disk_cache" => disk_cache = Some(v.trim().to_string()),
            _ => {
                if !apply_shared(&mut tuning, &mut headers, k, v).map_err(|e| at(n, e))? {
                    if is_site_only(k) {
                        return Err(at(n, format!("{k} belongs inside a site block")));
                    }
                    return Err(at(n, format!("unknown config key: {k}")));
                }
            }
        }
    }

    if let Some(s) = cur {
        return Err(at(s.line, "unclosed site block (missing '}')"));
    }
    if host.is_empty() || port.is_empty() {
        return Err("missing 'listen'".into());
    }
    if pending.is_empty() {
        return Err("at least one 'site <host> { ... }' block is required".into());
    }
    // Disk mode needs somewhere to write the snapshot; refuse to guess a path
    // (a wrong default on a tmpfs would silently keep everything in RAM).
    if storage == Storage::Disk && disk_cache.as_deref().unwrap_or("").is_empty() {
        return Err("storage = disk requires 'disk_cache = <path>' (a writable directory on real disk)".into());
    }

    // Resolve each site against the finished top-level defaults, so a block is
    // unaffected by where in the file those defaults were written.
    let mut sites: Vec<SiteConfig> = Vec::with_capacity(pending.len());
    for p in pending {
        let label = p.hosts.join(",");
        let cert = p
            .cert
            .ok_or_else(|| at(p.line, format!("site {label}: missing 'cert' (TLS terminates here even for a redirect-only host)")))?;
        let key = p
            .key
            .ok_or_else(|| at(p.line, format!("site {label}: missing 'key'")))?;
        // No root is legitimate (that is a redirect-only host), but no root and
        // no rules is a site that can only ever 404, which is never intended.
        if p.root.is_none() && p.redirects.is_empty() {
            return Err(at(
                p.line,
                format!("site {label}: needs a 'root' to serve, or at least one redirect rule"),
            ));
        }
        let (mut t, mut h) = (tuning, headers.clone());
        for (n, k, v) in &p.overrides {
            apply_shared(&mut t, &mut h, k, v).map_err(|e| at(*n, e))?;
        }
        sites.push(SiteConfig {
            hosts: p.hosts,
            root: p.root,
            cert,
            key,
            force_ssl: p.force_ssl,
            canonical_urls: p.canonical_urls,
            redirects: p.redirects,
            tuning: t,
            headers: h,
        });
    }

    Ok(Config {
        host,
        port,
        http_host,
        http_port,
        sites,
        headers,
        max_conns_per_ip,
        max_response_secs,
        storage,
        disk_cache,
    })
}

pub(crate) fn load_config(path: &str) -> Result<Config, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    parse_config(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> &'static str {
        "listen = [::]:443\nsite example.com {\n root = /var/www\n cert = /c.pem\n key = /k.pem\n}\n"
    }

    /// A config with `body` spliced in at the top level, on top of one valid site.
    fn with(body: &str) -> Result<Config, String> {
        parse_config(&format!(
            "listen = h:443\n{body}\nsite a.com {{\n root = /w\n cert = /c\n key = /k\n}}\n"
        ))
    }

    /// A config whose single site block contains `body`.
    fn site_with(body: &str) -> Result<Config, String> {
        parse_config(&format!(
            "listen = h:443\nsite a.com {{\n root = /w\n cert = /c\n key = /k\n{body}\n}}\n"
        ))
    }

    // ---- basic shape ----

    #[test]
    fn parses_a_minimal_config() {
        let c = parse_config(minimal()).unwrap();
        assert_eq!(c.host, "[::]");
        assert_eq!(c.port, "443");
        assert!(c.http_host.is_empty()); // no listen_http -> disabled sentinel
        assert_eq!(c.sites.len(), 1);
        assert_eq!(c.sites[0].hosts, vec!["example.com"]);
        assert_eq!(c.sites[0].root.as_deref(), Some("/var/www"));
        assert_eq!(c.sites[0].cert, "/c.pem");
        assert_eq!(c.sites[0].key, "/k.pem");
        assert!(c.sites[0].redirects.is_empty());
    }

    #[test]
    fn ipv6_listen_keeps_the_bracketed_host() {
        // rsplit on ':' must not shear the address literal.
        let c = with("").unwrap();
        assert_eq!(c.host, "h");
        let c = parse_config(&minimal().replace("[::]:443", "[2001:db8::1]:443")).unwrap();
        assert_eq!(c.host, "[2001:db8::1]");
        assert_eq!(c.port, "443");
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let text = "# a comment\n\n   \nlisten = 0.0.0.0:443\n# another\n\
                    site a.com {  # trailing comment\n root = /w\n cert = /c\n key = /k\n}\n";
        let c = parse_config(text).unwrap();
        assert_eq!(c.host, "0.0.0.0");
        assert_eq!(c.sites[0].hosts, vec!["a.com"]);
    }

    #[test]
    fn a_hash_inside_a_value_is_not_a_comment() {
        // Only a `#` at line start or after whitespace opens a comment, so a CSP
        // hash source or a URL fragment survives intact.
        let c = site_with("csp = default-src 'self' 'sha256-abc#def'").unwrap();
        assert_eq!(c.sites[0].headers.csp, "default-src 'self' 'sha256-abc#def'");
        let c = site_with("redirect /a -> /b#frag").unwrap();
        assert_eq!(c.sites[0].redirects.resolve("/a").unwrap(), "/b#frag");
    }

    #[test]
    fn multi_host_site_lowercases_and_splits() {
        let c = parse_config("listen = h:443\nsite A.com, WWW.a.com {\n root=/w\n cert=/c\n key=/k\n}\n")
            .unwrap();
        assert_eq!(c.sites[0].hosts, vec!["a.com", "www.a.com"]);
    }

    #[test]
    fn listen_http_is_parsed() {
        let c = with("listen_http = 0.0.0.0:80").unwrap();
        assert_eq!(c.http_host, "0.0.0.0");
        assert_eq!(c.http_port, "80");
    }

    // ---- structural errors ----

    #[test]
    fn missing_listen_is_rejected() {
        let e = parse_config("site a.com {\n root=/w\n cert=/c\n key=/k\n}\n").err().unwrap();
        assert!(e.contains("listen"), "{e}");
    }

    #[test]
    fn no_site_is_rejected() {
        let e = parse_config("listen = h:443\n").err().unwrap();
        assert!(e.contains("site"), "{e}");
    }

    #[test]
    fn empty_host_in_listen_http_is_rejected() {
        // `listen_http = :80` must not silently disable the plain listener.
        let e = with("listen_http = :80").err().unwrap();
        assert!(e.contains("listen_http"), "{e}");
    }

    #[test]
    fn listen_without_port_is_rejected() {
        assert!(with("").is_ok());
        assert!(parse_config("listen = hostonly\nsite a.com {\n root=/w\n cert=/c\n key=/k\n}\n").is_err());
    }

    #[test]
    fn malformed_line_without_equals_is_rejected() {
        let e = with("this is not valid").err().unwrap();
        assert!(e.contains("malformed"), "{e}");
    }

    #[test]
    fn unknown_key_is_rejected() {
        let e = with("bogus = x").err().unwrap();
        assert!(e.contains("unknown config key"), "{e}");
        let e = site_with("bogus = x").err().unwrap();
        assert!(e.contains("unknown site setting"), "{e}");
    }

    #[test]
    fn errors_carry_the_line_number() {
        let e = with("\n\nbogus = x").err().unwrap();
        assert!(e.starts_with("config line 4:"), "{e}");
    }

    #[test]
    fn an_unclosed_or_stray_brace_is_rejected() {
        let e = parse_config("listen = h:443\nsite a.com {\n root=/w\n cert=/c\n key=/k\n")
            .err()
            .unwrap();
        assert!(e.contains("unclosed"), "{e}");
        let e = parse_config("listen = h:443\n}\n").err().unwrap();
        assert!(e.contains("stray"), "{e}");
    }

    #[test]
    fn site_blocks_cannot_nest() {
        let e = parse_config("listen = h:443\nsite a.com {\nsite b.com {\n}\n}\n").err().unwrap();
        assert!(e.contains("nest"), "{e}");
    }

    #[test]
    fn a_site_without_a_brace_is_rejected() {
        let e = parse_config("listen = h:443\nsite a.com\n").err().unwrap();
        assert!(e.contains("open a block"), "{e}");
    }

    #[test]
    fn a_site_needs_a_cert_and_key() {
        let e = parse_config("listen = h:443\nsite a.com {\n root = /w\n key = /k\n}\n").err().unwrap();
        assert!(e.contains("missing 'cert'"), "{e}");
        let e = parse_config("listen = h:443\nsite a.com {\n root = /w\n cert = /c\n}\n").err().unwrap();
        assert!(e.contains("missing 'key'"), "{e}");
    }

    #[test]
    fn a_site_with_neither_root_nor_rules_is_rejected() {
        // It could only ever 404, so it is a mistake rather than a valid vhost.
        let e = parse_config("listen = h:443\nsite a.com {\n cert = /c\n key = /k\n}\n").err().unwrap();
        assert!(e.contains("root"), "{e}");
    }

    #[test]
    fn a_rootless_site_with_rules_is_a_redirect_only_host() {
        let c = parse_config(
            "listen = h:443\nsite www.a.com {\n cert=/c\n key=/k\n redirect * -> https://a.com$0\n}\n",
        )
        .unwrap();
        assert!(c.sites[0].root.is_none());
        assert_eq!(
            c.sites[0].redirects.resolve("/x/y").unwrap(),
            "https://a.com/x/y"
        );
    }

    // ---- helpful errors for the wrong syntax ----

    #[test]
    fn a_site_written_as_a_key_value_explains_the_block_form() {
        let e = parse_config("listen = h:443\nsite = a.com /w /c /k\n").err().unwrap();
        assert!(e.contains("a site is a block"), "{e}");
        // The operator's own values, rewritten.
        assert!(e.contains("site a.com {"), "{e}");
        assert!(e.contains("root = /w"), "{e}");
        assert!(e.contains("cert = /c"), "{e}");
        assert!(e.contains("key  = /k"), "{e}");
        // allow_http maps to the explicit setting, not silence.
        let e = parse_config("listen = h:443\nsite = a.com /w /c /k allow_http\n").err().unwrap();
        assert!(e.contains("force_ssl = off"), "{e}");
    }

    #[test]
    fn a_redirect_written_as_a_key_value_explains_the_rootless_block() {
        let e = with("redirect = www.a.com a.com /rc /rk").err().unwrap();
        assert!(e.contains("a site block with no root"), "{e}");
        assert!(e.contains("site www.a.com {"), "{e}");
        assert!(e.contains("redirect * -> https://a.com$0"), "{e}");
    }

    #[test]
    fn a_misplaced_directive_says_where_it_belongs() {
        let e = with("root = /w").err().unwrap();
        assert!(e.contains("belongs inside a site block"), "{e}");
        let e = site_with("max_total_bytes = 1G").err().unwrap();
        assert!(e.contains("server-level"), "{e}");
        assert!(e.contains("shared"), "{e}");
        let e = site_with("listen = h:443").err().unwrap();
        assert!(e.contains("server-level"), "{e}");
    }

    // ---- force_ssl ----

    #[test]
    fn force_ssl_defaults_to_on_and_can_be_turned_off() {
        assert!(with("").unwrap().sites[0].force_ssl, "secure default");
        assert!(site_with("force_ssl = on").unwrap().sites[0].force_ssl);
        assert!(!site_with("force_ssl = off").unwrap().sites[0].force_ssl);
        assert!(site_with("force_ssl = maybe").is_err());
    }

    #[test]
    fn force_ssl_is_per_site() {
        let c = parse_config(
            "listen = h:443\n\
             site a.com {\n root=/wa\n cert=/c\n key=/k\n force_ssl = on\n}\n\
             site b.com {\n root=/wb\n cert=/c\n key=/k\n force_ssl = off\n}\n",
        )
        .unwrap();
        assert!(c.sites[0].force_ssl);
        assert!(!c.sites[1].force_ssl);
    }

    #[test]
    fn canonical_urls_defaults_off_and_is_per_site() {
        assert!(!with("").unwrap().sites[0].canonical_urls, "off by default");
        assert!(site_with("canonical_urls = on").unwrap().sites[0].canonical_urls);
        assert!(!site_with("canonical_urls = off").unwrap().sites[0].canonical_urls);
        assert!(site_with("canonical_urls = maybe").is_err());
        // Site-only: at the top level it says where it belongs.
        let e = with("canonical_urls = on").err().unwrap();
        assert!(e.contains("belongs inside a site block"), "{e}");
    }

    // ---- redirect rules ----

    #[test]
    fn an_exact_rule_matches_only_that_path() {
        let c = site_with("redirect /old -> /new").unwrap();
        let r = &c.sites[0].redirects;
        assert_eq!(r.resolve("/old").unwrap(), "/new");
        assert!(r.resolve("/old/").is_none());
        assert!(r.resolve("/older").is_none());
        assert!(r.resolve("/").is_none());
    }

    #[test]
    fn a_prefix_rule_captures_the_remainder_as_dollar_one() {
        let c = site_with("redirect /docs/* -> /help/$1").unwrap();
        let r = &c.sites[0].redirects;
        assert_eq!(r.resolve("/docs/a/b").unwrap(), "/help/a/b");
        assert_eq!(r.resolve("/docs/").unwrap(), "/help/"); // empty remainder
        assert!(r.resolve("/docs").is_none(), "the prefix includes its slash");
    }

    #[test]
    fn dollar_zero_is_the_whole_path() {
        let c = site_with("redirect /a/* -> https://x.com$0").unwrap();
        assert_eq!(
            c.sites[0].redirects.resolve("/a/b").unwrap(),
            "https://x.com/a/b"
        );
    }

    #[test]
    fn the_catch_all_matches_anything_unmatched() {
        let c = site_with("redirect /keep -> /kept\nredirect * -> https://x.com$0").unwrap();
        let r = &c.sites[0].redirects;
        assert_eq!(r.resolve("/keep").unwrap(), "/kept");
        assert_eq!(r.resolve("/anything/else").unwrap(), "https://x.com/anything/else");
        assert_eq!(r.resolve("/").unwrap(), "https://x.com/");
    }

    #[test]
    fn the_longest_prefix_wins_regardless_of_file_order() {
        // Least specific listed first: the sort, not the order, must decide.
        let c = site_with("redirect /docs/* -> /a/$1\nredirect /docs/api/* -> /b/$1").unwrap();
        let r = &c.sites[0].redirects;
        assert_eq!(r.resolve("/docs/api/x").unwrap(), "/b/x");
        assert_eq!(r.resolve("/docs/other").unwrap(), "/a/other");
    }

    #[test]
    fn exact_beats_prefix_beats_catch_all() {
        let c = site_with(
            "redirect * -> /all\nredirect /a/* -> /pre/$1\nredirect /a/exact -> /hit",
        )
        .unwrap();
        let r = &c.sites[0].redirects;
        assert_eq!(r.resolve("/a/exact").unwrap(), "/hit");
        assert_eq!(r.resolve("/a/other").unwrap(), "/pre/other");
        assert_eq!(r.resolve("/z").unwrap(), "/all");
    }

    #[test]
    fn a_double_dollar_escapes_a_literal_dollar() {
        let c = site_with("redirect /a -> /b$$0").unwrap();
        assert_eq!(c.sites[0].redirects.resolve("/a").unwrap(), "/b$0");
    }

    #[test]
    fn a_lone_dollar_in_a_target_is_literal() {
        let c = site_with("redirect /a -> /b?x=$foo").unwrap();
        assert_eq!(c.sites[0].redirects.resolve("/a").unwrap(), "/b?x=$foo");
    }

    #[test]
    fn redirects_are_only_valid_inside_a_site_block() {
        let e = with("redirect /a -> /b").err().unwrap();
        assert!(e.contains("inside a site block"), "{e}");
    }

    #[test]
    fn malformed_redirect_rules_are_rejected() {
        let bad = |body: &str| site_with(body).is_err();
        assert!(bad("redirect /a /b"), "missing ->");
        assert!(bad("redirect -> /b"), "empty pattern");
        assert!(bad("redirect /a ->"), "empty target");
        assert!(bad("redirect a -> /b"), "pattern must be rooted or '*'");
        assert!(bad("redirect /a -> b"), "target must be rooted or absolute");
        assert!(bad("redirect /a -> example.com/b"), "scheme-less host");
        assert!(bad("redirect /a/*/b -> /c"), "'*' only as a trailing segment");
        assert!(bad("redirect /a* -> /c"), "'*' only after a '/'");
        assert!(bad("redirect /a -> /b$2"), "there is only one capture");
        assert!(bad("redirect /a -> /b$1"), "$1 is empty in an exact rule");
    }

    #[test]
    fn a_star_not_at_a_segment_boundary_is_rejected() {
        // `/a*` would have to mean "prefix /a", which reads as if it also matched
        // `/abc`; only `/a/*` is accepted so the meaning is never ambiguous.
        let e = site_with("redirect /a* -> /c").err().unwrap();
        assert!(e.contains("trailing /prefix/*"), "{e}");
    }

    #[test]
    fn self_redirects_are_rejected() {
        // Each of these would 301 a path to itself, forever. The `$0` spellings
        // are the same loop written differently, which a textual comparison of
        // target against pattern does not catch.
        for rule in [
            "redirect /a -> /a",
            "redirect /a/* -> /a/$1",
            "redirect * -> $0",
            "redirect /a -> $0",
            "redirect /a/* -> $0",
            // The next hop drops the fragment and the rule ignores the query, so
            // both of these come straight back to the same path.
            "redirect /a -> $0#top",
            "redirect /a -> $0?v=1",
        ] {
            let e = site_with(rule).err().unwrap_or_else(|| panic!("accepted: {rule}"));
            assert!(e.contains("itself"), "{rule}: {e}");
        }
        // `$1` alone is rejected before the loop check even runs: it expands to a
        // bare remainder, which would be a relative Location.
        assert!(site_with("redirect * -> $1").is_err());
    }

    #[test]
    fn a_rule_that_actually_moves_the_path_is_still_accepted() {
        // The loop check must not swallow legitimate rules that happen to use $0.
        for rule in [
            "redirect /a -> /b",
            "redirect /a -> https://example.com$0",
            "redirect /old/* -> /new/$1",
            "redirect * -> https://example.com$0",
            "redirect /a -> /b#top",
        ] {
            assert!(site_with(rule).is_ok(), "wrongly rejected: {rule}");
        }
    }

    #[test]
    fn duplicate_patterns_are_rejected() {
        assert!(site_with("redirect /a -> /b\nredirect /a -> /c").is_err());
        assert!(site_with("redirect /a/* -> /b/$1\nredirect /a/* -> /c/$1").is_err());
        assert!(site_with("redirect * -> /b\nredirect * -> /c").is_err());
    }

    #[test]
    fn a_control_byte_in_a_redirect_target_is_rejected() {
        let e = site_with("redirect /a -> /b\rX").err().unwrap();
        assert!(e.contains("control characters"), "{e}");
    }

    #[test]
    fn rules_are_per_site() {
        let c = parse_config(
            "listen = h:443\n\
             site a.com {\n root=/w\n cert=/c\n key=/k\n redirect /x -> /a\n}\n\
             site b.com {\n root=/w\n cert=/c\n key=/k\n}\n",
        )
        .unwrap();
        assert_eq!(c.sites[0].redirects.resolve("/x").unwrap(), "/a");
        assert!(c.sites[1].redirects.resolve("/x").is_none());
    }

    // ---- inherited / overridden settings ----

    #[test]
    fn a_site_inherits_the_server_level_defaults() {
        let c = parse_config(
            "listen = h:443\nbrotli_quality = 4\ncsp = default-src 'self'\n\
             site a.com {\n root=/w\n cert=/c\n key=/k\n}\n",
        )
        .unwrap();
        assert_eq!(c.sites[0].tuning.brotli_quality, 4);
        assert_eq!(c.sites[0].headers.csp, "default-src 'self'");
    }

    #[test]
    fn a_site_overrides_only_what_it_names() {
        let c = parse_config(
            "listen = h:443\nbrotli_quality = 4\ngzip_level = 3\n\
             site a.com {\n root=/w\n cert=/c\n key=/k\n brotli_quality = 9\n}\n",
        )
        .unwrap();
        assert_eq!(c.sites[0].tuning.brotli_quality, 9); // overridden
        assert_eq!(c.sites[0].tuning.gzip_level, 3); // inherited
    }

    #[test]
    fn a_top_level_default_applies_to_blocks_written_above_it() {
        // Deferred override resolution is what makes this order-independent.
        let c = parse_config(
            "listen = h:443\n\
             site a.com {\n root=/w\n cert=/c\n key=/k\n}\n\
             csp = default-src 'self'\n",
        )
        .unwrap();
        assert_eq!(c.sites[0].headers.csp, "default-src 'self'");
    }

    #[test]
    fn sites_do_not_leak_settings_into_each_other() {
        let c = parse_config(
            "listen = h:443\n\
             site a.com {\n root=/w\n cert=/c\n key=/k\n cache_max_age = 300\n}\n\
             site b.com {\n root=/w\n cert=/c\n key=/k\n}\n",
        )
        .unwrap();
        assert_eq!(c.sites[0].tuning.cache_max_age, 300);
        assert_eq!(c.sites[1].tuning.cache_max_age, 0);
    }

    #[test]
    fn every_shared_setting_is_overridable_per_site() {
        let c = site_with(
            "compression = off\n\
             brotli_quality = 5\n\
             gzip_level = 1\n\
             min_compress_bytes = 256\n\
             max_brotli_bytes = 2M\n\
             max_gzip_bytes = 16M\n\
             max_file_size = 32M\n\
             cache_max_age = 300\n\
             immutable_max_age = 604800\n\
             hsts_max_age = 300\n\
             hsts_include_subdomains = off\n\
             hsts_preload = no\n\
             csp = default-src 'self'",
        )
        .unwrap();
        let s = &c.sites[0];
        assert!(!s.tuning.compression);
        assert_eq!(s.tuning.brotli_quality, 5);
        assert_eq!(s.tuning.gzip_level, 1);
        assert_eq!(s.tuning.min_compress_bytes, 256);
        assert_eq!(s.tuning.max_brotli_bytes, 2 << 20);
        assert_eq!(s.tuning.max_gzip_bytes, 16 << 20);
        assert_eq!(s.tuning.max_file_size, 32 << 20);
        assert_eq!(s.tuning.cache_max_age, 300);
        assert_eq!(s.tuning.immutable_max_age, 604_800);
        assert_eq!(s.headers.hsts_max_age, 300);
        assert!(!s.headers.hsts_include_subdomains);
        assert!(!s.headers.hsts_preload);
        assert_eq!(s.headers.csp, "default-src 'self'");
    }

    #[test]
    fn a_bad_value_in_a_site_block_reports_that_line() {
        let e = site_with("brotli_quality = 12").err().unwrap();
        assert!(e.contains("config line"), "{e}");
        assert!(e.contains("brotli_quality"), "{e}");
    }

    // ---- defaults preserved from the previous format ----

    #[test]
    fn defaults_reproduce_the_previous_behaviour() {
        let c = parse_config(minimal()).unwrap();
        let t = c.sites[0].tuning;
        assert!(t.compression);
        assert_eq!(t.brotli_quality, 11);
        assert_eq!(t.gzip_level, 9);
        assert_eq!(t.min_compress_bytes, 64);
        assert_eq!(t.max_brotli_bytes, 8 << 20);
        assert_eq!(t.max_gzip_bytes, 64 << 20);
        assert_eq!(t.max_file_size, 256 << 20);
        assert_eq!(t.max_total_bytes, 2 << 30);
        assert_eq!(t.cache_max_age, 0);
        assert_eq!(t.immutable_max_age, 31_536_000);
        let h = &c.sites[0].headers;
        assert_eq!(h.hsts_max_age, 63_072_000);
        assert!(h.hsts_include_subdomains);
        assert!(h.hsts_preload);
        assert!(h.csp.is_empty());
        assert_eq!(c.max_conns_per_ip, 64);
        assert_eq!(c.max_response_secs, 0);
        assert!(c.sites[0].force_ssl);
        assert_eq!(c.storage, Storage::Memory);
        assert!(c.disk_cache.is_none());
    }

    #[test]
    fn server_level_directives_are_parsed() {
        let c = with("max_total_bytes = 1G\nmax_conns_per_ip = 8\nmax_response_secs = 120").unwrap();
        assert_eq!(c.sites[0].tuning.max_total_bytes, 1 << 30, "sites share the budget");
        assert_eq!(c.max_conns_per_ip, 8);
        assert_eq!(c.max_response_secs, 120);
    }

    #[test]
    fn an_absurd_duration_is_rejected_rather_than_panicking_later() {
        // `Instant + Duration` panics on overflow, and DeadlineIo builds one per
        // connection, so an unbounded value here would turn every request into a
        // worker-thread panic while the process kept reporting healthy.
        let e = with(&format!("max_response_secs = {}", u64::MAX)).err().unwrap();
        assert!(e.contains("at most"), "{e}");
        assert!(with("max_response_secs = 86400").is_ok(), "one day is still accepted");
    }

    #[test]
    fn a_control_byte_in_csp_is_rejected() {
        let e = with("csp = default-src\rself").err().unwrap();
        assert!(e.contains("control characters"), "{e}");
    }

    #[test]
    fn storage_defaults_to_memory_and_disk_requires_a_cache_dir() {
        let e = with("storage = disk").err().unwrap();
        assert!(e.contains("disk_cache"), "{e}");
        let c = with("storage = disk\ndisk_cache = /var/cache/bs").unwrap();
        assert_eq!(c.storage, Storage::Disk);
        assert_eq!(c.disk_cache.as_deref(), Some("/var/cache/bs"));
    }

    #[test]
    fn an_unknown_storage_value_is_rejected() {
        assert!(with("storage = ssd").is_err());
    }

    #[test]
    fn default_header_render_emits_the_documented_block() {
        // The header block documented in docs/CONFIGURATION.md, byte for byte.
        let expected = "X-Content-Type-Options: nosniff\r\n\
                        X-Frame-Options: SAMEORIGIN\r\n\
                        Referrer-Policy: strict-origin-when-cross-origin\r\n\
                        Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
                        Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n";
        assert_eq!(HeaderConfig::default().render(), expected);
    }

    #[test]
    fn header_render_reflects_hsts_and_csp_config() {
        // HSTS disabled -> no STS line at all.
        let off = HeaderConfig { hsts_max_age: 0, ..Default::default() };
        assert!(!off.render().contains("Strict-Transport-Security"));
        // Trimmed HSTS + CSP.
        let h = HeaderConfig {
            hsts_max_age: 100,
            hsts_include_subdomains: false,
            hsts_preload: false,
            csp: "default-src 'self'".into(),
        };
        let r = h.render();
        assert!(r.contains("Strict-Transport-Security: max-age=100\r\n"));
        assert!(!r.contains("includeSubDomains") && !r.contains("preload"));
        assert!(r.contains("Content-Security-Policy: default-src 'self'\r\n"));
    }

    // ---- value parsing ----

    #[test]
    fn size_suffixes_are_binary_and_optional() {
        let sz = |v: &str| site_with(&format!("max_file_size = {v}")).unwrap().sites[0].tuning.max_file_size;
        assert_eq!(sz("1048576"), 1_048_576); // bare bytes
        assert_eq!(sz("1K"), 1024);
        assert_eq!(sz("1k"), 1024); // case-insensitive
        assert_eq!(sz("8M"), 8 << 20);
        assert_eq!(sz("2G"), 2 << 30);
    }

    #[test]
    fn boolean_forms_are_accepted() {
        let b = |v: &str| site_with(&format!("compression = {v}")).unwrap().sites[0].tuning.compression;
        for y in ["on", "true", "yes", "1", "ON", "True"] {
            assert!(b(y), "{y} should be true");
        }
        for n in ["off", "false", "no", "0", "OFF"] {
            assert!(!b(n), "{n} should be false");
        }
    }

    #[test]
    fn out_of_range_and_malformed_tuning_is_rejected() {
        let bad = |line: &str| site_with(line).is_err();
        assert!(bad("brotli_quality = 12"), "brotli max is 11");
        assert!(bad("gzip_level = 10"), "gzip max is 9");
        assert!(bad("brotli_quality = abc"));
        assert!(bad("compression = maybe"));
        assert!(bad("max_file_size = 10X"), "unknown size suffix");
        assert!(bad("max_file_size = "), "empty size");
        assert!(bad("cache_max_age = soon"));
    }

    #[test]
    fn size_overflow_is_rejected_not_wrapped() {
        // 2e10 * 1GiB overflows usize; must error rather than wrap to a tiny cap.
        let e = with("max_total_bytes = 20000000000G").err().unwrap();
        assert!(e.contains("overflow"), "{e}");
    }

    #[test]
    fn a_repeated_directive_takes_the_last_value() {
        let c = with("brotli_quality = 2\nbrotli_quality = 7").unwrap();
        assert_eq!(c.sites[0].tuning.brotli_quality, 7);
        let c = site_with("brotli_quality = 2\nbrotli_quality = 7").unwrap();
        assert_eq!(c.sites[0].tuning.brotli_quality, 7);
    }

    #[test]
    fn values_tolerate_surrounding_whitespace() {
        let c = site_with("  compression   =   off  \n  max_file_size = 4M  ").unwrap();
        assert!(!c.sites[0].tuning.compression);
        assert_eq!(c.sites[0].tuning.max_file_size, 4 << 20);
        // ...and so do redirect rules.
        let c = site_with("   redirect    /a    ->    /b   ").unwrap();
        assert_eq!(c.sites[0].redirects.resolve("/a").unwrap(), "/b");
    }

    // ---- file I/O ----

    #[test]
    fn load_config_reads_and_parses_a_file() {
        let mut path = std::env::temp_dir();
        path.push(format!("bare-server-cfg-{}-{}.conf", std::process::id(), line!()));
        std::fs::write(&path, minimal()).unwrap();
        let c = load_config(path.to_str().unwrap()).expect("loads");
        assert_eq!(c.host, "[::]");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_config_on_a_missing_file_errors() {
        let e = load_config("/nonexistent/definitely/not/here.conf").err().unwrap();
        assert!(e.contains("cannot read"), "{e}");
    }
}
