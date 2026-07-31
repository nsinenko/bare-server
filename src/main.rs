//! bare-server — an absolute-minimum static file server with TLS termination.
//!
//! Design:
//!   - At boot the whole document root is loaded into an immutable in-memory
//!     table (URL -> bytes + mime). For ordinary content the filesystem is
//!     never touched again, so user-controlled paths never reach the disk and
//!     path traversal is structurally impossible: a bad path simply is not a
//!     key -> 404. The one deliberate exception is the ACME http-01 challenge
//!     (`/.well-known/acme-challenge/<token>`), which is read from disk per
//!     request so an ACME client can renew without a restart; that path is confined to
//!     a `[A-Za-z0-9_-]` token and refuses symlinks at every level (see
//!     `serve_acme_token`), so it does not reopen the traversal surface.
//!   - One worker thread per connection, capped by a semaphore.
//!   - HTTP/1.1 GET/HEAD, keep-alive, TCP_NODELAY.
//!   - TLS 1.2/1.3 via rustls + ring (forward-secret AEAD suites only).

use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, Stream};

mod banner;
mod cache;
mod config;
mod mime;
#[cfg(test)]
mod testutil;

use crate::cache::{
    build_cache, cache_bytes, file_signature, sample, tls_signature, tree_signature, Cache, Cached,
    DiskVariant, ErrorPages, Sampled, Site, Sites, StatusResponse, Variant, Vhosts,
};
use crate::config::{load_config, Config};

const MAX_HEADER_BYTES: usize = 8192;
// What we advertise to 0-RTT clients, and what we are willing to buffer from
// them. rustls spends this single value on *plaintext* when it accepts the early
// data but on *ciphertext* (record length, ~plaintext + AEAD tag + record
// overhead) when it rejects it — stale ticket, cache eviction, restart, config
// reload — and arms trial decryption against it. So the advertised limit and the
// reject-skip budget are the same number, and a client that fills the advertised
// limit exactly still overruns it on reject by the AEAD expansion, turning a
// routine 0-RTT rejection into a fatal DecryptError instead of a 1-RTT fallback.
// The margin here does not come from the value itself; it comes from
// MAX_HEADER_BYTES: a conforming request head is <= 8192 bytes and is 431'd
// above that (see serve_over), so the early data a conforming client actually
// sends is at most MAX_HEADER_BYTES, which — at 2x below this ceiling — clears
// the ciphertext skip budget with room to spare even after AEAD expansion. It
// must also be advertised and buffered in one place: buffering less than we
// advertise would silently truncate a conforming client's request mid-stream.
const MAX_EARLY_DATA_BYTES: usize = 2 * MAX_HEADER_BYTES;
const MAX_PATH_LEN: usize = 1024;
const MAX_CONNS: usize = 1024; // HTTPS concurrency cap (anti-DoS)
const MAX_CONNS_HTTP: usize = 256; // separate cap: :80 only issues redirects
const MAX_REQS_PER_CONN: usize = 1000; // keep-alive request cap
const IO_TIMEOUT_SECS: u64 = 15; // per-read/write socket timeout + idle timeout
// The cache and compression limits are server-level config directives
// (`max_file_size`, `max_total_bytes`, `max_brotli_bytes`, `max_gzip_bytes`,
// `brotli_quality`, ...) so they can be tuned per host without a rebuild. Their
// defaults, and the reasoning behind each, live with `config::Tuning`.
const WATCH_INTERVAL_SECS: u64 = 2; // poll interval for hot-reload watcher
// A reload can fail transiently: a cert written a moment after its key, a port
// still held by a draining process. Marking such an attempt "applied" would
// abandon it forever, so failures are retried — but retrying every 2s would log
// every 2s for a permanently broken config, so the delay doubles up to this.
const MAX_RELOAD_BACKOFF_SECS: u64 = 60;

// Wall-clock bounds. The socket timeouts above are per-syscall and every byte
// received resets them, so on their own they let a client dribbling one byte at
// a time hold a connection slot for hours. These are absolute: measured with
// Instant, never reset by traffic.
const HEADER_TIMEOUT_SECS: u64 = 10; // to finish sending one request head
const HANDSHAKE_TIMEOUT_SECS: u64 = 10; // to finish the TLS handshake
const CONN_MAX_SECS: u64 = 300; // keep-alive lifetime cap, checked between requests
// Progress window for the in-flight response, enforced at the socket below
// rustls (see DeadlineIo). Once handle_request starts writing it does not return
// until the whole body is out, so CONN_MAX_SECS cannot bound it; but bounding it
// by absolute wall-clock would truncate a legitimately slow large download.
// Comfortably above the 15s socket timeout so one slow-but-progressing syscall is
// never mistaken for a stall.
const PROGRESS_TIMEOUT_SECS: u64 = 30;
// How much a response must actually deliver within one PROGRESS_TIMEOUT_SECS
// window. A pure "did any byte move" test is defeated by a client that reads one
// byte every few seconds: each byte resets the timer, so the connection — with
// its thread, fd, and both permits — is pinned indefinitely while costing the
// attacker nothing (measured: one slot held 344s for 43 bytes). Requiring a
// minimum *rate* instead separates a slow link from a deliberate stall. 1 KiB
// per 30s is a floor of ~34 B/s: four orders of magnitude below any real client,
// and ~270x above what that attack sustains.
const MIN_PROGRESS_BYTES: usize = 1024;
const MAX_HANDSHAKE_ROUNDS: usize = 64; // read_tls iterations before giving up

// Per-connection memory. Everything here is multiplied by MAX_CONNS, so the
// defaults matter: at the 1024-connection cap they are the difference between
// ~92 MB and ~44 MB of worst-case heap.
//
// rustls buffers up to DEFAULT_BUFFER_LIMIT (64 KiB) of ciphertext per
// connection before write_tls drains it to the socket. 16 KiB is still ~one
// full TLS record, so a response is written in the same number of records —
// just drained in more, smaller batches.
const TLS_BUFFER_LIMIT: usize = 16 * 1024;
// Initial request-head buffer. It grows geometrically and a real request head
// is well under 1 KiB, so sizing it at MAX_HEADER_BYTES only pre-pays 8 KiB on
// every connection for a ceiling almost none of them reach.
const INITIAL_BUF_BYTES: usize = 2048;
// Reserved stack per connection thread. Lazily faulted, so this is address
// space rather than resident memory, but it still bounds how many threads fit
// under a strict-overcommit or constrained-address-space limit.
const THREAD_STACK_BYTES: usize = 128 * 1024;

// The baseline security headers sent on every response (including errors) are
// built from config: `HeaderConfig::render` in config.rs produces the block,
// `Policy` bakes it into every cached response, and `Vhosts::security_headers`
// carries the same Arc to the on-the-fly error/redirect/304 paths.
// `hsts_max_age`, `hsts_*`, and `csp` tune it. HSTS also goes out over plain
// HTTP, but RFC 6797 §8.1 makes a UA ignore it there, so it is inert rather
// than wrong.

/// The one URI prefix that must stay reachable over plain HTTP: ACME http-01
/// writes its challenge here, so redirecting it to HTTPS would break renewal.
const ACME_PREFIX: &str = "/.well-known/acme-challenge/";
// Bounds on a live-read http-01 token. A key authorization is ~90 bytes; the
// token itself is base64url of 128 bits, i.e. 43 chars. Both limits are set an
// order of magnitude above that purely to keep a stray file from being served.
const ACME_TOKEN_MAX_LEN: usize = 128;
const ACME_TOKEN_MAX_BYTES: u64 = 4096;

fn fatal(msg: &str) -> ! {
    eprintln!("bare-server: {msg}");
    std::process::exit(1);
}

/// Background hot-reload. Every tick it checks three things:
///
///   1. the config file — a change rebuilds the whole runtime (sites *and* the
///      TLS/SNI certs), so new sites can be added or removed without a restart;
///   2. the cert and key files themselves — nothing else notices an ACME
///      renewal: the PEMs live outside every document root, the config file is
///      untouched by the ACME client, and the process has no reload signal
///      handler. Left
///      unwatched, it would happily serve its boot-time certificate until it
///      expired, and a process supervisor never restarts a healthy process. A
///      cert-only change rebuilds *just* the TLS config and swaps it over the
///      live content caches, so a renewal costs an O(certs) reload, not a full
///      re-walk and re-compression of every site;
///   3. each live site's document tree — a change rebuilds just that cache.
///
/// All three are debounced: a change must stay stable for one interval before it
/// is applied, so a half-finished rsync or a half-written PEM never goes live.
/// New state is built off to the side and swapped in atomically, and a failed
/// rebuild keeps the old state rather than taking the server down.
fn watch(
    config_path: String,
    boot: Sampled,
    shared: SharedRuntime,
    https: &mut ListenerCtl,
    http: &mut Option<ListenerCtl>,
    // Connection limits, applied to any listener started or rebound here and
    // re-read from the config on every reload. They are the controls an operator
    // reaches for while a flood is in progress, so a restart to change them would
    // put the mitigation out of reach exactly when it is wanted. (The compile-time
    // MAX_CONNS caps above really are startup-fixed.)
    mut max_conns_per_ip: usize,
    response_secs: Arc<AtomicU64>,
) -> ! {
    let mut tls_files = boot.tls_files;
    // `applied` comes from the pre-build sample, `last` from a fresh read: if the
    // config, a cert or a file changed while the boot runtime was being built,
    // the two differ and the next tick reloads. See `Sampled`. Reading the config
    // signature fresh here (post-build) instead of taking boot.config would lose
    // exactly the edit the sample exists to catch.
    let mut cfg_applied = boot.config;
    let mut cfg_last = file_signature(&config_path);
    let mut links_last = cache::root_links_of(&config_path);
    let mut tls_last = tls_signature(&tls_files);
    let mut tls_applied = boot.tls;
    // Seeded from the pre-build sample, which is keyed by canonical root; the
    // scan below re-keys per Site on its first pass and both maps converge on
    // that keying from then on.
    let mut tree_applied: HashMap<String, u64> = HashMap::new();
    for (host, site) in current(&shared).vhosts.sites.iter() {
        let Some(r) = site.root.as_ref() else { continue };
        let rk = r.display().to_string();
        if let Some(sig) = boot.trees.get(&rk) {
            tree_applied.insert(site_key(host, &rk), *sig);
        }
    }
    let mut tree_last: HashMap<String, u64> = HashMap::new();
    for (host, site) in current(&shared).vhosts.sites.iter() {
        let Some(r) = site.root.as_ref() else { continue };
        let rk = r.display().to_string();
        tree_last.insert(site_key(host, &rk), tree_signature(r));
    }
    // What each *configured* root resolved to when the live runtime was built.
    // `build_vhosts` keeps only the canonicalised directory, so without this a
    // release-flip deploy (`/srv/www -> releases/43`) is invisible: nothing under
    // the path being watched changed. See `cache::root_links`.
    let mut links_applied = boot.links;
    // Listener addresses the live config asks for, still to be reconciled. Kept
    // separate from the runtime rebuild so a busy port is retried with a bare
    // bind() rather than by recompressing every site again.
    let mut pending: Option<(String, Option<String>)> = None;
    let mut retry_at: Option<Instant> = None;
    let mut backoff = Duration::from_secs(WATCH_INTERVAL_SECS);
    let mut failed_at: Option<(u64, u64)> = None;
    let mut last_err: Option<String> = None;
    // Roots whose last content rebuild failed, keyed to the signature that
    // failed. A failed rebuild does not advance `tree_applied`, so it is retried
    // every tick — but it must not re-log every tick, so a root logs once per
    // distinct failing signature (the config path has its own backoff for this).
    let mut tree_failed: HashMap<String, u64> = HashMap::new();

    loop {
        thread::sleep(Duration::from_secs(WATCH_INTERVAL_SECS));

        // ---- 1. config file and TLS material ----
        let cfg_now = file_signature(&config_path);
        let mut tls_now = tls_signature(&tls_files);
        // An edit (or a renewal) after the failure is not the same failure:
        // drop the backoff so the operator's fix is picked up immediately.
        if failed_at.is_some_and(|s| s != (cfg_now, tls_now)) {
            retry_at = None;
            backoff = Duration::from_secs(WATCH_INTERVAL_SECS);
            failed_at = None;
        }
        // A config edit rebuilds everything (sites *and* certs); a change to only
        // the cert/key files rebuilds just the TLS config. The two are handled by
        // separate arms below so a certificate renewal does not trigger a full re-walk
        // and re-compression of every document root — see the cert-only arm.
        // A configured root now resolving somewhere else is a deploy, not an
        // edit: re-resolve through the full config path so the new directory is
        // canonicalised, walked, and watched from here on. Debounced like
        // everything else — the flip must still be there next tick.
        let links_now = cache::root_links_of(&config_path);
        let links_changed = links_now.as_ref().is_some_and(|l| *l != links_applied)
            && links_now == links_last;
        let cfg_changed =
            (cfg_now != cfg_applied && cfg_now == cfg_last) || links_changed;
        let tls_changed = tls_now != tls_applied && tls_now == tls_last;
        let changed = cfg_changed || tls_changed;
        let due = retry_at.is_none_or(|t| Instant::now() >= t);

        if due && (changed || pending.is_some()) {
            let mut failure: Option<String> = None;

            if cfg_changed {
                match load_config(&config_path) {
                    Err(e) => failure = Some(e),
                    Ok(cfg) => {
                        // Sample before building — see `Sampled`. cfg_now was
                        // already read pre-build above, so the config file's own
                        // signature is captured correctly without re-reading it.
                        let s = sample(&config_path, &cfg);
                        match build_runtime(&cfg) {
                            Err(e) => failure = Some(e),
                            Ok(rt) => {
                                let hosts: Vec<&str> =
                                    rt.vhosts.sites.keys().map(|s| s.as_str()).collect();
                                let summary = hosts.join(", ");
                                // Re-seed tree signatures for the new site set,
                                // keyed per Site exactly as the content scan
                                // below keys them.
                                tree_last.clear();
                                tree_applied.clear();
                                for (host, site) in rt.vhosts.sites.iter() {
                                    let Some(root) = site.root.as_ref() else { continue };
                                    let rk = root.display().to_string();
                                    let pre = s
                                        .trees
                                        .get(&rk)
                                        .copied()
                                        .unwrap_or_else(|| tree_signature(root));
                                    let k = site_key(host, &rk);
                                    tree_applied.insert(k.clone(), pre);
                                    tree_last.insert(k, tree_signature(root));
                                }
                                // The roots this build resolved to, so a later
                                // symlink flip under a configured path is seen.
                                links_applied = s.links.clone();
                                *shared.write().unwrap_or_else(PoisonError::into_inner) =
                                    Arc::new(rt);
                                // Connection limits, applied over the live
                                // listeners. Without this the reload logs
                                // success while both settings keep their boot
                                // values — the worst possible outcome for a
                                // control an operator is changing under load.
                                max_conns_per_ip = cfg.max_conns_per_ip;
                                response_secs.store(cfg.max_response_secs, Ordering::Relaxed);
                                https.peer.set_max(max_conns_per_ip);
                                if let Some(h) = http.as_ref() {
                                    h.peer.set_max(max_conns_per_ip);
                                }
                                eprintln!("bare-server: config reloaded — serving: {summary}");

                                cfg_applied = cfg_now;
                                tls_files = s.tls_files;
                                tls_applied = s.tls;
                                tls_now = tls_signature(&tls_files);
                                // Reconcile listeners after the swap: the new
                                // runtime is already live, so a rebound socket
                                // serves the new sites immediately.
                                pending = Some((
                                    format!("{}:{}", cfg.host, cfg.port),
                                    if cfg.http_host.is_empty() {
                                        None
                                    } else {
                                        Some(format!("{}:{}", cfg.http_host, cfg.http_port))
                                    },
                                ));
                            }
                        }
                    }
                }
            } else if tls_changed {
                // Certificates rotated but the config is otherwise unchanged —
                // the common case: an ACME renewal, which touches only the
                // PEM files. Rebuild JUST the TLS config and swap it over the
                // existing content caches. A renewal must not cost a full re-walk
                // and re-brotli of every document root (minutes, during which the
                // watcher thread is blocked); reusing the live `vhosts` Arc makes
                // it an O(certs) operation instead. In-flight connections already
                // hold their own ServerConfig Arc, so the swap only affects
                // handshakes that begin after it.
                match load_config(&config_path) {
                    Err(e) => failure = Some(e),
                    Ok(cfg) => match build_tls(&cfg) {
                        // A half-written PEM fails to parse or pair: keep the old
                        // certificate and let the debounce/backoff retry.
                        Err(e) => failure = Some(e),
                        Ok(new_tls) => {
                            let cur = current(&shared);
                            let rt = Runtime { vhosts: Arc::clone(&cur.vhosts), tls: new_tls };
                            *shared.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rt);
                            tls_applied = tls_now;
                            eprintln!("bare-server: certificates reloaded");
                        }
                    },
                }
            }

            if let Some((https_addr, want_http)) = pending.clone() {
                let mut ok = true;
                if let Err(e) = rebind(https, &https_addr, &shared) {
                    ok = false;
                    failure = failure.or(Some(e));
                }
                // Only reconcile the HTTP listener once HTTPS is settled. The
                // (Some, None) arm retires port 80 irreversibly for this pending
                // — so doing it while the HTTPS rebind is still failing would
                // strand the process with no HTTP listener AND the wrong HTTPS
                // address, a torn state the retry loop cannot walk back. If HTTPS
                // failed, leave HTTP untouched and retry the whole thing.
                if ok {
                    match (&mut *http, want_http) {
                        (Some(ctl), Some(addr)) => {
                            if let Err(e) = rebind(ctl, &addr, &shared) {
                                ok = false;
                                failure = failure.or(Some(e));
                            }
                        }
                        (Some(ctl), None) => {
                            retire(ctl);
                            eprintln!("bare-server: HTTP listener on {} stopped", ctl.addr);
                            *http = None;
                        }
                        (None, Some(addr)) => {
                            match start_listener(
                                &addr,
                                MAX_CONNS_HTTP,
                                max_conns_per_ip,
                                Arc::clone(&response_secs),
                                false,
                                "HTTP",
                                &shared,
                            ) {
                                Ok(c) => {
                                    eprintln!("bare-server: HTTP listener started on {addr}");
                                    *http = Some(c);
                                }
                                Err(e) => {
                                    ok = false;
                                    failure = failure.or(Some(e));
                                }
                            }
                        }
                        (None, None) => {}
                    }
                }
                if ok {
                    pending = None;
                }
            }

            match failure {
                None => {
                    retry_at = None;
                    backoff = Duration::from_secs(WATCH_INTERVAL_SECS);
                    failed_at = None;
                    last_err = None;
                }
                Some(e) => {
                    // Log the first failure and any change of cause, but not
                    // every retry: a permanently unbindable address would
                    // otherwise fill the journal forever.
                    if last_err.as_deref() != Some(e.as_str()) {
                        eprintln!("bare-server: reload FAILED ({e}); keeping previous state");
                        last_err = Some(e);
                    }
                    failed_at = Some((cfg_now, tls_now));
                    retry_at = Some(Instant::now() + backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(MAX_RELOAD_BACKOFF_SECS));
                }
            }
        }
        cfg_last = cfg_now;
        tls_last = tls_now;
        links_last = links_now;

        // ---- 2. each site's content ----
        // Several hostnames can alias the same Site, so key the scan by document
        // root: the tree is hashed once and one rebuild serves every alias.
        let rt = current(&shared);
        // One entry per distinct Site, NOT per root. Several hostnames can alias
        // a single Site and share its `Arc` — those want one rebuild between
        // them. But two separate `site` blocks naming the same root are two
        // Sites, with two caches and two policies (a block may override headers,
        // compression, cache-control), so rebuilding one and recording the root
        // as done leaves the other serving boot-time content for the life of the
        // process — and which one loses is decided by HashMap iteration order,
        // so it differs from start to start. Keying by identity rebuilds each.
        // Redirect-only sites have no tree and are simply not in the scan.
        let mut targets: HashMap<usize, (Arc<Site>, std::path::PathBuf, String)> = HashMap::new();
        for (host, site) in rt.vhosts.sites.iter() {
            let Some(r) = &site.root else { continue };
            match targets.entry(Arc::as_ptr(site) as usize) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Hostnames are unique across sites, so the smallest one is a
                    // stable name for this Site from one tick to the next.
                    if host < &e.get().2 {
                        e.get_mut().2 = host.clone();
                    }
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert((Arc::clone(site), r.clone(), host.clone()));
                }
            }
        }
        // Hash each distinct tree once, even when several Sites share it.
        let mut sigs: HashMap<String, u64> = HashMap::new();
        for (_, root, _) in targets.values() {
            sigs.entry(root.display().to_string()).or_insert_with(|| tree_signature(root));
        }

        for (site, site_root, host) in targets.values() {
            let root = site_root.display().to_string();
            // Per-Site key, so two blocks sharing a root do not share a slot.
            let key = site_key(host, &root);
            let now = sigs.get(&root).copied().unwrap_or(0);
            let last = tree_last.get(&key).copied().unwrap_or(now);
            let applied = tree_applied.get(&key).copied().unwrap_or(now);
            if now != applied && now == last {
                // Charge the rebuild against a global budget, not a fresh one:
                // seed `total` with the bytes every *other* live root currently
                // holds, so a reload cannot push aggregate resident memory past
                // MAX_TOTAL_BYTES the way a per-root budget silently could. (The
                // rebuilt root's own old cache is still resident until the swap
                // below; MAX_TOTAL_BYTES' comment already sizes the host for that
                // one transient 2x.)
                let mut total: usize = targets
                    .values()
                    .filter(|(s, _, _)| !Arc::ptr_eq(s, site))
                    .map(|(s, _, _)| {
                        cache_bytes(&s.cache.read().unwrap_or_else(std::sync::PoisonError::into_inner).map)
                    })
                    .sum();
                // The precomputed error responses stay resident across a rebuild,
                // because a reload replaces caches and never policies. So charge
                // them here too, exactly as `build_vhosts` charged them at boot.
                total += error_page_bytes(&rt.vhosts);
                let before = total;
                // This site's own policy: its block may have overridden the
                // compression or cache-control settings the server-level values
                // would have given it.
                match build_cache(site_root, &mut total, &site.policy) {
                    Some(new_cache) => {
                        let n = new_cache.map.len();
                        let bytes = total - before;
                        *site.cache.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Arc::new(new_cache);
                        eprintln!(
                            "bare-server: hot-reloaded {root} for {host} ({n} files, {bytes} bytes)"
                        );
                        // Success: mark applied so we stop rebuilding, and clear
                        // any prior failure record for this site.
                        tree_applied.insert(key.clone(), now);
                        tree_failed.remove(&key);
                    }
                    None => {
                        // Do NOT advance tree_applied: leaving now != applied
                        // means the next tick retries once the root is readable
                        // and under budget again. Log only on a new failing sig.
                        if tree_failed.get(&key) != Some(&now) {
                            eprintln!(
                                "bare-server: reload of {root} for {host} aborted (unreadable root or over size budget); keeping old cache"
                            );
                            tree_failed.insert(key.clone(), now);
                        }
                    }
                }
            }
            tree_last.insert(key, now);
        }
    }
}

/// Watcher key for one site's document tree. Two `site` blocks may name the same
/// root, so the root alone does not identify whose cache is being tracked; the
/// host is unique across sites and stable across ticks. NUL cannot occur in
/// either part, so the join is unambiguous.
fn site_key(host: &str, root: &str) -> String {
    format!("{host}\u{0}{root}")
}

// ------------------------------------------------------ concurrency limiter

/// A minimal counting semaphore; `acquire` returns an RAII permit that releases
/// on drop, so a slot is freed even if the worker thread panics.
struct Semaphore {
    count: Mutex<usize>,
    cv: Condvar,
}
struct Permit(Arc<Semaphore>);

impl Semaphore {
    fn new(n: usize) -> Arc<Self> {
        Arc::new(Semaphore { count: Mutex::new(n), cv: Condvar::new() })
    }
    // Poison is recovered rather than propagated, matching how the site caches
    // are handled. Nothing under this guard can panic today, but a panic here
    // would be on the accept loop, i.e. the whole server, for a counter that is
    // still perfectly consistent.
    /// Take a slot, or give up after `wait` so the caller can re-check something
    /// else. The timeout is not optional: a retiring accept loop only notices its
    /// generation bumped *after* `accept()` returns, and it cannot reach
    /// `accept()` while every permit is held — so a saturated listener would
    /// otherwise keep its socket bound long after the operator was told it had
    /// stopped, which is precisely when someone is trying to close the port.
    fn acquire_timeout(self: &Arc<Self>, wait: Duration) -> Option<Permit> {
        let mut c = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        let deadline = Instant::now() + wait;
        while *c == 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let (guard, _) = self
                .cv
                .wait_timeout(c, left)
                .unwrap_or_else(PoisonError::into_inner);
            c = guard;
        }
        *c -= 1;
        Some(Permit(Arc::clone(self)))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut c = self.0.count.lock().unwrap_or_else(PoisonError::into_inner);
        *c += 1;
        self.0.cv.notify_one();
    }
}

/// Per-source-IP concurrency cap. The global `Semaphore` bounds total
/// connections but not how they are distributed, so one peer can hold every
/// slot (Finding 6). This caps how many a single IP may hold at once; a
/// `PeerPermit` is released on drop, so a slot frees even if the worker panics.
/// `max == 0` disables it entirely (e.g. behind a shared-IP proxy, where every
/// connection would otherwise count against one address).
struct PeerLimiter {
    /// Hot-reloadable. This is exactly the control an operator reaches for while
    /// a flood is in progress, so requiring a restart to change it would mean the
    /// mitigation is unavailable precisely when it is needed.
    max: AtomicUsize,
    counts: Mutex<HashMap<IpAddr, usize>>,
}
struct PeerPermit {
    limiter: Arc<PeerLimiter>,
    ip: IpAddr,
    /// Whether this permit incremented the counter. `max` can change while the
    /// permit is alive, so Drop has to undo what `try_acquire` actually did
    /// rather than re-deriving it from the setting in force at drop time.
    counted: bool,
}

impl PeerLimiter {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(PeerLimiter { max: AtomicUsize::new(max), counts: Mutex::new(HashMap::new()) })
    }
    fn set_max(&self, max: usize) {
        self.max.store(max, Ordering::Relaxed);
    }
    fn max(&self) -> usize {
        self.max.load(Ordering::Relaxed)
    }
    /// Reserve a slot for `ip`, or None if it is already at the cap. When
    /// disabled (`max == 0`) it never tracks and never refuses.
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PeerPermit> {
        let max = self.max();
        if max == 0 {
            return Some(PeerPermit { limiter: Arc::clone(self), ip, counted: false });
        }
        let mut m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(PeerPermit { limiter: Arc::clone(self), ip, counted: true })
    }
}
impl Drop for PeerPermit {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut m = self.limiter.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.ip); // don't let the map grow without bound
            }
        }
    }
}

// ------------------------------------------------------------ HTTP handling

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Is a request head strictly framed? It must use only CRLF line breaks and
/// carry no stray control bytes. This is what closes the request-smuggling
/// surface: `split("\r\n")` alone treats a bare LF as an ordinary character, so
/// a header hidden behind a bare LF (or a lone CR) is invisible to the
/// body-framing check — the classic CL.0/TE.0 desync. A NUL or other C0 control
/// in a field is illegal per RFC 9110 §5.5 regardless. HTAB is the one control a
/// field value may legitimately contain; a *leading* HTAB is obs-fold and is
/// rejected per-line by the header loop, not here.
fn well_formed_head(head: &[u8]) -> bool {
    let mut i = 0;
    while i < head.len() {
        match head[i] {
            b'\r' => {
                if head.get(i + 1) != Some(&b'\n') {
                    return false; // bare CR
                }
                i += 2;
                continue;
            }
            b'\n' => return false,             // LF not preceded by CR
            0x7f => return false,              // DEL
            c if c < 0x20 && c != b'\t' => return false, // other C0 control
            _ => {}
        }
        i += 1;
    }
    true
}

/// Is a q-value zero? "0", "0.", "0.0", "0.000" are; everything else is not.
fn is_zero_q(v: &str) -> bool {
    let mut c = v.chars();
    if c.next() != Some('0') {
        return false;
    }
    match c.next() {
        None => true,
        Some('.') => c.all(|ch| ch == '0'),
        _ => false,
    }
}

/// Does the client accept `token`? Parses Accept-Encoding as RFC 9110 §12.5.3
/// defines it — comma-separated codings, each with an optional ";q=" weight —
/// rather than testing for a bare substring. A substring test cannot see a
/// `q=0` refusal, and matches inside unrelated codings ("br" inside "brotli").
/// `token` must be lowercase. An absent header means identity only.
fn accepts_encoding(field: &str, token: &str) -> bool {
    let mut wildcard: Option<bool> = None;
    for part in field.split(',') {
        let mut it = part.split(';');
        let name = it.next().unwrap_or("").trim();
        let mut acceptable = true;
        for param in it {
            let param = param.trim();
            // `get(..2)`, not `param[..2]`: the field is raw network input, and
            // a byte-length check is not a char-boundary check — indexing a
            // multi-byte char (`gzip;\u{20ac}`) would panic the worker thread.
            if param.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("q=")) {
                acceptable = !is_zero_q(param[2..].trim());
            }
        }
        if name.eq_ignore_ascii_case(token) {
            return acceptable; // an explicit entry wins over any wildcard
        }
        if name == "*" {
            wildcard = Some(acceptable);
        }
    }
    wildcard.unwrap_or(false)
}

/// Does this If-None-Match field list `etag`? Compares whole entity-tags, using
/// the weak comparison RFC 9110 §8.8.3.2 requires for If-None-Match, instead of
/// a substring test that any longer tag containing this one would satisfy.
fn inm_matches(field: &str, etag: &str) -> bool {
    let field = field.trim();
    if field == "*" {
        return true;
    }
    field.split(',').any(|t| {
        let t = t.trim();
        let t = t.strip_prefix("W/").unwrap_or(t);
        t.strip_prefix('"').and_then(|t| t.strip_suffix('"')).unwrap_or(t) == etag
    })
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode; reject NUL, control bytes, and malformed escapes. The result
/// is only ever used as a lookup key, never a filesystem path.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = if b[i] == b'%' {
            if i + 2 >= b.len() {
                return None;
            }
            let v = (hexval(b[i + 1])? << 4) | hexval(b[i + 2])?;
            i += 2;
            v
        } else {
            b[i]
        };
        if c == 0 || c < 0x20 || c == 0x7f {
            return None;
        }
        out.push(c);
        i += 1;
    }
    Some(out)
}

/// Percent-encode a decoded path for a `Location` header. Everything RFC 3986
/// lets a path segment carry unescaped (unreserved + sub-delims + ":@") plus the
/// separator itself is passed through; everything else — space, `%`, `?`, `#`,
/// and every non-ASCII byte — is escaped. Emitting the decoded path verbatim
/// would produce a Location that re-parses as a different URL the moment a name
/// contains one of those, which is exactly the duplicate-spelling problem the
/// canonicalisation exists to remove.
fn percent_encode_path(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let bare = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if bare {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// What a request path resolved to.
enum Resolved<'a> {
    /// Servable right here at the requested URL.
    Entry(&'a Cached),
    /// "/blog" matched "/blog/index.html". Deliberately not servable as-is: the
    /// document's base directory would be "/" instead of "/blog/", so every
    /// document-relative reference in it ("style.css") would resolve one level
    /// too high and 404. The caller redirects to the trailing-slash form.
    DirIndex,
}

/// Map a request path to a cache entry, supporting extensionless "clean" URLs.
/// Every candidate is just a key lookup in the immutable table — no filesystem
/// access — so this adds no traversal surface.
///   "/about"   -> "/about"  ->  "/about.html"  ->  "/about/index.html" (301)
///   "/about/"  -> "/about/index.html"  ->  "/about.html"
///   "/"        -> "/index.html"
fn resolve<'a>(cache: &'a Cache, decoded: &str) -> Option<Resolved<'a>> {
    if decoded.ends_with('/') {
        let idx = format!("{decoded}index.html");
        if let Some(e) = cache.get(&idx) {
            return Some(Resolved::Entry(e));
        }
        let trimmed = decoded.trim_end_matches('/');
        if !trimmed.is_empty() {
            let html = format!("{trimmed}.html");
            if let Some(e) = cache.get(&html) {
                return Some(Resolved::Entry(e));
            }
        }
        None
    } else {
        if let Some(e) = cache.get(decoded) {
            return Some(Resolved::Entry(e));
        }
        let html = format!("{decoded}.html");
        if let Some(e) = cache.get(&html) {
            return Some(Resolved::Entry(e));
        }
        // Both of the fallbacks above serve a document whose real location has
        // the same base directory as the URL asked for; this one does not, so
        // it only reports the hit and leaves the answer to the caller.
        cache
            .get(&format!("{decoded}/index.html"))
            .map(|_| Resolved::DirIndex)
    }
}

/// Read an ACME token file with no symlink-follow and no hardlink escape,
/// verifying every property on the *opened handle* (fstat) rather than on the
/// path, so there is no check-then-use window. The previous lstat-then-`fs::read`
/// pattern was a TOCTOU a local writer of the challenge dir could win, swapping
/// the token for a symlink between the check and the read to disclose an
/// arbitrary file. Two handle-based defenses close it:
///   - `O_NOFOLLOW`: if the final path component is a symlink the open itself
///     fails atomically — there is no separate check to race;
///   - `nlink == 1`: a hardlink planted in the challenge dir pointing at a file
///     outside the root is a real regular file `O_NOFOLLOW` cannot catch, so
///     refuse anything with more than one link (a genuine ACME token has one).
/// Returns None on any failure, which the caller turns into a 404. The parent
/// directory checks in `serve_acme_token` remain best-effort against a static
/// layout; swapping a *parent* dir for a symlink mid-request is a much narrower
/// residual that still requires local write access to the document root.
fn read_token_file(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = fs::OpenOptions::new()
        .read(true)
        // O_NOFOLLOW refuses a symlink. O_NONBLOCK is what keeps a *FIFO*
        // planted in the challenge directory from parking this worker inside
        // open(2) forever: a read-only open of a FIFO blocks until a writer
        // appears, and that happens before the is_file() check below can reject
        // it. Nothing upstream recovers — the socket timeouts bound I/O on the
        // socket, not a syscall on a local path — so the thread would hold its
        // connection slot for the life of the process, and MAX_CONNS_HTTP of
        // them take the plain listener down for good, breaking ACME renewal.
        // On a regular file O_NONBLOCK has no effect on reads.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > ACME_TOKEN_MAX_BYTES {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    // Bound the read itself, not just the size fstat reported: the file can
    // grow between that check and this read, and read_to_end would follow it.
    f.take(ACME_TOKEN_MAX_BYTES).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// Serve an ACME http-01 token straight from disk — the one request path that
/// touches the filesystem, and it has to.
///
/// an ACME client writes the token and asks the CA to validate immediately; the
/// watcher's 2-tick debounce plus a full-root rebuild (brotli q11 on every
/// file) means the cache cannot possibly carry the token in time, so a
/// cache-only answer is a 404, the authorization fails, and the certificate
/// eventually expires.
///
/// Traversal is structurally impossible rather than checked-for: the remainder
/// of the path must be a single segment drawn from the ACME token alphabet, so
/// it can contain neither '/' nor '.', and symlinks are refused at every level —
/// exactly as `walk` refuses them.
fn serve_acme_token<W: Write>(
    tls: &mut W,
    root: &Path,
    decoded: &str,
    keep_alive: bool,
    is_head: bool,
    policy: &cache::Policy,
) -> io::Result<bool> {
    let tok = &decoded[ACME_PREFIX.len()..];
    let well_formed = !tok.is_empty()
        && tok.len() <= ACME_TOKEN_MAX_LEN
        && tok.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    // lstat every component below the (canonical) root and refuse a symlink at
    // any of them. Checking the token file alone is not enough: opening it by
    // path follows a symlinked *parent* dir too, so a `.well-known` or
    // `acme-challenge` symlink pointing outside the root would serve an
    // arbitrary matching file (a private key, a system credential file)
    // unauthenticated over :80.
    // `walk` holds this invariant for the cache; the live ACME read must match.
    let no_symlink = |p: &Path| matches!(fs::symlink_metadata(p), Ok(m) if !m.file_type().is_symlink());
    let well_known = root.join(".well-known");
    let challenge = well_known.join("acme-challenge");
    let body = if well_formed && no_symlink(&well_known) && no_symlink(&challenge) {
        read_token_file(&challenge.join(tok))
    } else {
        None
    };
    let body = match body {
        Some(b) => b,
        None => {
            send_error(tls, &policy.errors.not_found, keep_alive, is_head)?;
            return Ok(keep_alive);
        }
    };
    // no-store: the token is single-use and deleted right after validation.
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: {}\r\n\
         {}\r\n",
        body.len(),
        if keep_alive { "keep-alive" } else { "close" },
        policy.security_headers
    );
    // One write, like every other response. The token cannot be precomputed,
    // since it is read live by design, but the buffer can still be joined: a
    // token is at most ACME_TOKEN_MAX_BYTES.
    let mut full = Vec::with_capacity(head.len() + body.len());
    full.extend_from_slice(head.as_bytes());
    if !is_head {
        full.extend_from_slice(&body);
    }
    tls.write_all(&full)?;
    tls.flush()?;
    Ok(keep_alive)
}

/// Emit one of the server's own status responses, meaning every 4xx and 5xx this
/// process generates. The bytes were baked at boot by `ErrorPages`, so this is
/// one `write_all`: one TLS record, one syscall, zero allocation. Building the
/// head and body separately cost two `rustls` round trips per error, because
/// `rustls::Stream::write` runs `complete_io` after every write.
fn send_error<W: Write>(
    tls: &mut W,
    resp: &StatusResponse,
    keep_alive: bool,
    is_head: bool,
) -> io::Result<()> {
    tls.write_all(resp.bytes(keep_alive, is_head))?;
    tls.flush()
}

/// Build the authority (host, plus `:port` only when it is not the scheme's
/// default) for a redirect `Location`. A standard :443/:80 deployment emits a
/// clean `https://host/…`; a non-standard port (dev, testing, or a box behind a
/// port-mapping) stays reachable because the port it actually listens on is
/// carried over instead of being silently dropped to 443/80.
fn redirect_authority(host: &str, port: &str, default: &str) -> String {
    if port.is_empty() || port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// The one place this server emits a redirect. Every caller — a configured
/// rule, the HTTP -> HTTPS upgrade, the trailing-slash canonicalisation — goes
/// through here, so the status is `301 Moved Permanently` everywhere by
/// construction rather than by three code paths agreeing.
///
/// `location` must already be control-character-free: rule targets are checked
/// when the config is parsed, and the request bytes spliced into them (and into
/// the other two callers' Locations) were validated before any of this ran.
fn send_redirect<W: Write>(
    tls: &mut W,
    location: &str,
    keep_alive: bool,
    hdrs: &str,
) -> io::Result<()> {
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: {}\r\n\
         {}\r\n",
        if keep_alive { "keep-alive" } else { "close" },
        hdrs
    );
    tls.write_all(resp.as_bytes())?;
    tls.flush()
}

/// The canonical form of a URL path that spells itself with `.html`, or `None`
/// if the path is already canonical and should be served.
///
/// A site built from directory-index files reaches the same document under
/// several URLs — `/about/`, `/about/index.html`, and (historically) a flat
/// `/about.html`. Only the first is canonical; the rest are duplicate content
/// that a search engine has to be told about. This folds all of them onto the
/// directory form:
///
/// ```text
///   /index.html       -> /
///   /foo/index.html   -> /foo/
///   /foo.html         -> /foo/
///   /foo/bar.html     -> /foo/bar/
///   /myindex.html     -> /myindex/     (only a whole "index" segment counts)
/// ```
///
/// The result never ends in `.html`, so the redirect it produces can never
/// match again — one hop, no loop, whatever the path.
fn canonical_form(path: &str) -> Option<String> {
    let stem = path.strip_suffix(".html")?;
    Some(match stem.strip_suffix("index") {
        // "index" only counts as the whole last segment: "/myindex.html" is an
        // ordinary page whose name merely ends in those five letters.
        Some(dir) if dir.is_empty() || dir.ends_with('/') => dir.to_string(),
        _ => format!("{stem}/"),
    })
}

/// Normalize a Host header to a lookup key: lowercase, strip any :port
/// (and handle a bracketed IPv6 literal).
fn normalize_host(h: &str) -> String {
    let h = h.trim();
    let base = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or(h)
    } else {
        h.split(':').next().unwrap_or(h)
    };
    base.to_ascii_lowercase()
}

/// Handle one already-buffered request head against the configured `sites`.
/// Returns whether to keep the connection alive for another request.
///
/// `sni` is the server name the TLS handshake selected a certificate for, or
/// `None` on the plain listener.
fn handle_request<W: Write>(
    tls: &mut W,
    head: &[u8],
    vhosts: &Vhosts,
    want_ka: bool,
    redirect_https: bool,
    sni: Option<&str>,
) -> io::Result<bool> {
    // Everything answerable before a host resolves is an error: a 400 on a
    // malformed head, a 404 for an unknown Host. Only the server-level
    // precomputed set is needed here. The site's own header block is picked up
    // below, once there is a site.
    let errs: &ErrorPages = &vhosts.errors;
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        Err(_) => {
            send_error(tls, &errs.bad_request, false, false)?;
            return Ok(false);
        }
    };
    // Strict framing before anything is parsed out of the head: only CRLF line
    // breaks, no stray control bytes. A bare LF or lone CR would let a header
    // hide from the body-framing check below (a CL.0/TE.0 desync); a control
    // byte in a field is illegal per RFC 9110 §5.5. See `well_formed_head`.
    if !well_formed_head(head) {
        send_error(tls, &errs.bad_request, false, false)?;
        return Ok(false);
    }

    let mut lines = text.split("\r\n");
    let reqline = lines.next().unwrap_or("");
    let mut parts = reqline.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    // Needed this early because the error paths below can already answer a HEAD
    // request, and those responses must not carry a body.
    let is_head = method == "HEAD";
    // A request-line is exactly three space-separated fields. Trailing junk
    // ("GET / HTTP/1.1 x") is rejected rather than discarded: lenient
    // request-line parsing is the same class of defect as header smuggling.
    if parts.next().is_some() {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false);
    }
    if method.is_empty() || target.is_empty() || version.is_empty() {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false);
    }
    // Only the two HTTP versions this server actually speaks. An unrecognised
    // version token is rejected rather than assumed, so garbage cannot reach
    // the rest of the pipeline.
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false);
    }

    // The whole target, path AND query, is interpolated into `Location` on the
    // redirect paths below. Reject every control byte in the target instead of
    // escaping at Location-construction time, which would mangle legitimately
    // percent-encoded query strings. `split(' ')` already excludes spaces.
    if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false);
    }

    // Single pass over headers: keep-alive, Accept-Encoding, Host, If-None-Match,
    // and body framing. Only HTTP/1.1 defaults keep-alive on.
    let mut keep_alive = version == "HTTP/1.1";
    let (mut accept_enc, mut host_hdr, mut inm) = ("", "", "");
    let mut host_seen = false;
    let mut has_body = false;
    for line in lines {
        // A blank line terminates the header block.
        if line.is_empty() {
            break;
        }
        // obs-fold (a header continued onto the next line by leading whitespace)
        // is obsolete and a smuggling vector: the folded line's real content
        // hides behind the leading SP/HTAB, past the name checks below. Refuse
        // it rather than unfold it.
        if line.starts_with(' ') || line.starts_with('\t') {
            send_error(tls, &errs.bad_request, false, is_head)?;
            return Ok(false);
        }
        // field-line = field-name ":" OWS field-value OWS. No colon, an empty
        // name, or whitespace *inside* the name ("Content-Length :") is
        // malformed, and the last is exactly how a header sneaks past a prefix
        // match, so it is a hard error, not something to skip.
        let (name, value) = match line.split_once(':') {
            Some((n, v)) => (n, v.trim()),
            None => {
                send_error(tls, &errs.bad_request, false, is_head)?;
                return Ok(false);
            }
        };
        if name.is_empty() || name.bytes().any(|b| b == b' ' || b == b'\t') {
            send_error(tls, &errs.bad_request, false, is_head)?;
            return Ok(false);
        }
        if name.eq_ignore_ascii_case("host") {
            // Exactly one Host (RFC 9110 §7.2). Multiple Host fields are a
            // host-confusion primitive whenever a front-end and this server
            // disagree on which wins, so refuse them rather than last-wins.
            if host_seen {
                send_error(tls, &errs.bad_request, false, is_head)?;
                return Ok(false);
            }
            host_seen = true;
            host_hdr = value;
        } else if name.eq_ignore_ascii_case("content-length") {
            // A declared body is never read off the wire: this server has no
            // method that takes one. Left unhandled, those bytes stay in the
            // connection buffer and the keep-alive loop parses them as the NEXT
            // request head: a CL.0 desync, one request in, two responses out.
            // Content-Length: 0 is a real bodyless request some clients send, so
            // it is allowed; anything else is refused and the connection closed.
            if value != "0" {
                has_body = true;
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            has_body = true; // chunked is not implemented; never guess
        } else if name.eq_ignore_ascii_case("connection") {
            // Tokenised, not a substring test: "not-closed-yet" must not match
            // "close". An explicit token overrides the version default.
            for tok in value.split(',') {
                let tok = tok.trim();
                if tok.eq_ignore_ascii_case("close") {
                    keep_alive = false;
                } else if tok.eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            }
        } else if name.eq_ignore_ascii_case("if-none-match") {
            inm = value;
        } else if name.eq_ignore_ascii_case("accept-encoding") {
            accept_enc = value;
        }
    }
    if !want_ka {
        keep_alive = false;
    }
    if has_body {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false); // close: the undrained body must never be re-parsed
    }

    // Host allowlist: only configured virtual hosts are served. Everything
    // else gets 404: missing Host, unknown Host, direct-IP probes.
    // This runs BEFORE any redirect on purpose: every Location below is built
    // from this validated key, never from the raw Host header, so a forged Host
    // cannot turn us into an open redirector.
    let host_key = normalize_host(host_hdr);
    // Bind the request to the name the connection was established for. The
    // certificate comes from SNI but everything else (root, redirect rules,
    // CSP, HSTS) comes from Host, and nothing compared them: a client could
    // SNI `a.example`, receive a's certificate, then send `Host: b.example` and
    // be served b's content under a's certificate and a's security-header
    // policy. HTTP/1.1 has no legitimate reason to do that (this server speaks
    // no HTTP/2, so there is no connection coalescing to accommodate), so treat
    // the mismatch as the unknown host it effectively is.
    if sni.is_some_and(|s| s != host_key) {
        send_error(tls, &errs.not_found, keep_alive, is_head)?;
        return Ok(keep_alive);
    }
    let site = match vhosts.sites.get(&host_key) {
        Some(s) => s,
        None => {
            send_error(tls, &errs.not_found, keep_alive, is_head)?;
            return Ok(keep_alive);
        }
    };
    // From here the site is known, so its own header block applies: a per-site
    // `csp` or `hsts_max_age` covers this site's errors and redirects, not just
    // the 200s the cache baked it into. Its errors were baked with that block.
    let hdrs: &str = &site.policy.security_headers;
    let errs: &ErrorPages = &site.policy.errors;

    if method != "GET" && !is_head {
        send_error(tls, &errs.method_not_allowed, keep_alive, is_head)?;
        return Ok(keep_alive);
    }

    let path = target.split('?').next().unwrap_or("");
    // Reject absolute-form / malformed targets before they can reach Location.
    if path.is_empty() || !path.starts_with('/') || path.len() >= MAX_PATH_LEN {
        send_error(tls, &errs.bad_request, false, is_head)?;
        return Ok(false);
    }
    // The query string with its leading '?', or empty. Re-attached to a redirect
    // Location below so a rule does not silently drop it.
    let query = target.find('?').map_or("", |p| &target[p..]);

    // Decode once, up front. Everything below that reasons about *which document*
    // a URL names (the canonical-URL fold, the ACME exemption, the cache
    // lookup) has to agree on one spelling of the path, or they disagree about
    // the same resource: RFC 3986 §6.2.2.2 makes "/ab%6Fut.html" and
    // "/about.html" the same URI, and canonicalising the raw form let
    // "/about%2Ehtml" skip the fold entirely while still being served.
    // Only the redirect rules below stay on the raw path. That is documented
    // behaviour, so that a pattern matches the bytes a client actually sent.
    let decoded = match percent_decode(path).and_then(|b| String::from_utf8(b).ok()) {
        Some(d) => d,
        None => {
            send_error(tls, &errs.bad_request, false, is_head)?;
            return Ok(false);
        }
    };

    // The ACME http-01 challenge is exempt from every redirect below: the CA
    // fetches it over plain HTTP and, while it does follow redirects, it must
    // stay answerable here or renewal breaks. A redirect-only host can opt into
    // renewal the same way by giving its block a `root` pointing at the webroot.
    let is_acme = decoded.starts_with(ACME_PREFIX);

    // Scheme for a rule target that is a bare path. On the plain listener a site
    // that redirects to HTTPS anyway goes straight to https, so a rule and the
    // upgrade below cost one hop between them rather than two.
    let (scheme, authority) = if redirect_https && !site.force_ssl {
        ("http", redirect_authority(&host_key, &vhosts.http_port, "80"))
    } else {
        ("https", redirect_authority(&host_key, &vhosts.https_port, "443"))
    };

    // Configured redirect rules, on either listener. `path` is the raw request
    // path (percent-encoding intact, query stripped); the query is re-attached
    // unless the rule's own target already carries one. Every target came from
    // the config and every byte spliced into it was validated above, so the
    // result is safe to put in a header.
    if !is_acme {
        if let Some(to) = site.redirects.resolve(path) {
            let location = match (to.starts_with("https://") || to.starts_with("http://"), to.contains('?')) {
                (true, true) => to,
                (true, false) => format!("{to}{query}"),
                (false, true) => format!("{scheme}://{authority}{to}"),
                (false, false) => format!("{scheme}://{authority}{to}{query}"),
            };
            send_redirect(tls, &location, keep_alive, hdrs)?;
            return Ok(keep_alive);
        }
    }

    // Canonical URL shape, after the explicit rules so a rule for a page that
    // *moved* still answers in one hop rather than being folded onto its own
    // old directory first. Computed on the decoded path and re-encoded for the
    // header: a feature whose whole job is to collapse duplicate spellings of a
    // URL must not emit a Location that is itself a non-canonical spelling.
    if site.canonical_urls && !is_acme {
        if let Some(canon) = canonical_form(&decoded) {
            send_redirect(
                tls,
                &format!("{scheme}://{authority}{}{query}", percent_encode_path(&canon)),
                keep_alive,
                hdrs,
            )?;
            return Ok(keep_alive);
        }
    }

    // Per site (ON by default, `force_ssl = off` opts out): the :80 listener
    // upgrades this host's traffic to HTTPS. `target` keeps the query string and
    // is control-character-free because it was explicitly validated above.
    if redirect_https && !is_acme && site.force_ssl {
        let auth = redirect_authority(&host_key, &vhosts.https_port, "443");
        send_redirect(tls, &format!("https://{auth}{target}"), keep_alive, hdrs)?;
        return Ok(keep_alive);
    }

    // Past the rules, so this request wants content. A redirect-only site has
    // none — its cache is empty, so the lookups below simply 404.
    //
    // Clone the current cache Arc under a brief read lock; holding it pins this
    // snapshot so a concurrent hot-reload swap cannot pull the data out from
    // under an in-flight request.
    let cache_arc = site
        .cache
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let cache: &Cache = &cache_arc.map;

    // ACME http-01 tokens bypass the cache entirely and are read live, because the
    // debounced rebuild cannot publish them before the CA fetches them. A site
    // with no root has nowhere to read one from, so it 404s like any other path.
    if is_acme {
        return match &site.root {
            Some(root) => serve_acme_token(tls, root, &decoded, keep_alive, is_head, &site.policy),
            None => {
                send_error(tls, &errs.not_found, keep_alive, is_head)?;
                Ok(keep_alive)
            }
        };
    }

    let entry = match resolve(cache, &decoded) {
        Some(Resolved::Entry(e)) => e,
        // "/blog" is a directory index: canonicalise to "/blog/" first, so the
        // browser bases the document's relative references on the right
        // directory. The Location is the decoded path re-encoded, so the hop
        // lands on one canonical spelling whatever the client sent, and carries
        // the query string over. Prefixing the validated `host_key` also keeps a
        // path that starts with "//" from being read as a protocol-relative URL.
        //
        // This canonicalisation preserves the current scheme: over the plain
        // listener a site that serves HTTP (a `force_ssl` one already redirected
        // to HTTPS above) stays on http:// rather than being silently upgraded,
        // and either way the Location names the port actually being listened on
        // — `scheme`/`authority` were resolved once, above, for this same reason.
        Some(Resolved::DirIndex) => {
            send_redirect(
                tls,
                &format!("{scheme}://{authority}{}/{query}", percent_encode_path(&decoded)),
                keep_alive,
                hdrs,
            )?;
            return Ok(keep_alive);
        }
        None => {
            send_error(tls, &errs.not_found, keep_alive, is_head)?;
            return Ok(keep_alive);
        }
    };

    // Memory and disk entries share the same negotiation and conditional-GET
    // rules; only where the body comes from differs (a precomputed buffer vs a
    // file streamed from the snapshot).
    match entry {
        Cached::Mem(m) => serve_mem(tls, m, accept_enc, inm, keep_alive, is_head, &site.policy),
        Cached::Disk(d) => serve_disk(tls, d, accept_enc, inm, keep_alive, is_head, &site.policy),
    }
}

/// Emit a 304 Not Modified. Repeats the headers a cache needs to keep its stored
/// 200 usable (ETag, Content-Encoding, Vary, Cache-Control), without which a
/// shared cache could hand a stored brotli body to a client that never asked for
/// one. Shared by both storage backends.
fn send_304<W: Write>(
    tls: &mut W,
    etag: &str,
    encoding: Option<&'static str>,
    vary: bool,
    cache_control: &str,
    keep_alive: bool,
    hdrs: &str,
) -> io::Result<()> {
    let mut resp = format!("HTTP/1.1 304 Not Modified\r\nETag: \"{etag}\"\r\n");
    if let Some(enc) = encoding {
        resp.push_str("Content-Encoding: ");
        resp.push_str(enc);
        resp.push_str("\r\n");
    }
    if vary {
        resp.push_str("Vary: Accept-Encoding\r\n");
    }
    resp.push_str("Cache-Control: ");
    resp.push_str(cache_control);
    resp.push_str("\r\nConnection: ");
    resp.push_str(if keep_alive { "keep-alive" } else { "close" });
    resp.push_str("\r\n");
    resp.push_str(hdrs);
    resp.push_str("\r\n");
    tls.write_all(resp.as_bytes())?;
    tls.flush()
}

/// Serve a fully in-memory entry: pick the best precomputed encoding and write
/// its one contiguous buffer. This is the original hot path, unchanged.
fn serve_mem<W: Write>(
    tls: &mut W,
    entry: &cache::MemEntry,
    accept_enc: &str,
    inm: &str,
    keep_alive: bool,
    is_head: bool,
    policy: &cache::Policy,
) -> io::Result<bool> {
    let variant: &Variant =
        if let Some(br) = entry.br.as_ref().filter(|_| accepts_encoding(accept_enc, "br")) {
            br
        } else if let Some(gz) = entry.gzip.as_ref().filter(|_| accepts_encoding(accept_enc, "gzip"))
        {
            gz
        } else {
            &entry.identity
        };

    if !inm.is_empty() && inm_matches(inm, &variant.etag) {
        send_304(
            tls,
            &variant.etag,
            variant.encoding,
            entry.vary,
            &entry.cache_control,
            keep_alive,
            &policy.security_headers,
        )?;
        return Ok(keep_alive);
    }

    if keep_alive {
        // Hot path: one write of the precomputed buffer.
        if is_head {
            tls.write_all(&variant.full_ka[..variant.header_len])?;
        } else {
            tls.write_all(&variant.full_ka)?;
        }
    } else {
        // Rare close path: reuse the baked header, just flip the Connection value.
        let header = String::from_utf8_lossy(&variant.full_ka[..variant.header_len])
            .replacen("Connection: keep-alive", "Connection: close", 1);
        tls.write_all(header.as_bytes())?;
        if !is_head {
            tls.write_all(&variant.full_ka[variant.header_len..])?;
        }
    }
    tls.flush()?;
    Ok(keep_alive)
}

/// Serve a disk-backed entry: pick the best encoding, write its precomputed
/// header, then stream the body from the snapshot file. The header is written
/// only after the file opens, so a missing/short file becomes a clean error
/// rather than a header promising a body that never arrives.
fn serve_disk<W: Write>(
    tls: &mut W,
    entry: &cache::DiskEntry,
    accept_enc: &str,
    inm: &str,
    keep_alive: bool,
    is_head: bool,
    policy: &cache::Policy,
) -> io::Result<bool> {
    let variant: &DiskVariant =
        if let Some(br) = entry.br.as_ref().filter(|_| accepts_encoding(accept_enc, "br")) {
            br
        } else if let Some(gz) = entry.gzip.as_ref().filter(|_| accepts_encoding(accept_enc, "gzip"))
        {
            gz
        } else {
            &entry.identity
        };

    if !inm.is_empty() && inm_matches(inm, &variant.etag) {
        send_304(
            tls,
            &variant.etag,
            variant.encoding,
            entry.vary,
            &entry.cache_control,
            keep_alive,
            &policy.security_headers,
        )?;
        return Ok(keep_alive);
    }

    // Header: baked with Connection: keep-alive, flipped for the close path.
    let header: std::borrow::Cow<[u8]> = if keep_alive {
        std::borrow::Cow::Borrowed(&variant.header_ka)
    } else {
        std::borrow::Cow::Owned(
            String::from_utf8_lossy(&variant.header_ka)
                .replacen("Connection: keep-alive", "Connection: close", 1)
                .into_bytes(),
        )
    };

    if is_head {
        // HEAD carries no body, so there is nothing to stream, just the header.
        tls.write_all(&header)?;
        tls.flush()?;
        return Ok(keep_alive);
    }

    // Open before writing the header: if the snapshot file is gone (should never
    // happen, since the BuildDir is pinned by this cache Arc), fail closed instead of
    // committing a header whose Content-Length we cannot honour.
    let mut file = match fs::File::open(&variant.path) {
        Ok(f) => f,
        Err(_) => {
            send_error(tls, &policy.errors.internal_error, false, is_head)?;
            return Ok(false);
        }
    };
    tls.write_all(&header)?;
    stream_body(tls, &mut file, variant.len)?;
    tls.flush()?;
    Ok(keep_alive)
}

/// Copy exactly `len` bytes from `file` to `tls` in bounded chunks. Each write
/// goes through the same writer as everything else, so the no-progress deadline
/// (and any absolute transfer cap) applies to a disk stream just as it does to
/// an in-memory one.
fn stream_body<W: Write>(tls: &mut W, file: &mut fs::File, len: u64) -> io::Result<()> {
    let mut buf = [0u8; 64 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let n = file.read(&mut buf)?;
        if n == 0 {
            // The immutable snapshot is shorter than indexed — should not happen.
            // Stop rather than spin; the client sees a short (truncated) body.
            break;
        }
        let take = (n as u64).min(remaining) as usize;
        tls.write_all(&buf[..take])?;
        remaining -= take as u64;
    }
    Ok(())
}

/// Drive one TLS connection: keep-alive request loop, preserving pipelined bytes.
fn handle_connection(
    mut sock: TcpStream,
    tls_config: Arc<ServerConfig>,
    vhosts: Arc<Vhosts>,
    max_response_secs: u64,
) {
    let conn_deadline = Instant::now() + Duration::from_secs(CONN_MAX_SECS);
    let _ = sock.set_nodelay(true);
    let t = Some(Duration::from_secs(IO_TIMEOUT_SECS));
    let _ = sock.set_read_timeout(t);
    let _ = sock.set_write_timeout(t);

    let mut conn = match ServerConnection::new(tls_config) {
        Ok(c) => c,
        Err(_) => return,
    };
    conn.set_buffer_limit(Some(TLS_BUFFER_LIMIT));

    // Drive the handshake manually so any TLS 1.3 0-RTT early data the client
    // sends in its first flight is captured into `buf` before we start reading
    // normal application data. If 0-RTT is not used, `buf` simply stays empty
    // and this is an ordinary blocking handshake.
    let mut buf: Vec<u8> = Vec::with_capacity(INITIAL_BUF_BYTES);
    let handshake_deadline = Instant::now() + Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let mut rounds = 0usize;
    loop {
        while conn.wants_write() {
            if conn.write_tls(&mut sock).is_err() {
                return;
            }
        }
        if !conn.is_handshaking() {
            break;
        }
        // Bound the handshake itself. Every read_tls gets a fresh socket
        // timeout, so a client trickling a fragmented ClientHello could
        // otherwise hold a connection slot indefinitely without ever reaching
        // the request loop and its deadlines.
        rounds += 1;
        if rounds > MAX_HANDSHAKE_ROUNDS || Instant::now() >= handshake_deadline {
            return;
        }
        match conn.read_tls(&mut sock) {
            Ok(0) => return, // client closed mid-handshake
            Ok(_) => {}
            Err(_) => return, // timeout / error
        }
        if conn.process_new_packets().is_err() {
            // rustls has queued a fatal alert (e.g. access_denied when the SNI
            // resolver has no cert for the requested name). Push it out before
            // dropping the socket, otherwise the peer sees a bare connection
            // reset and cannot tell a missing vhost from a firewall drop. The
            // write timeout set above bounds this.
            while conn.wants_write() {
                if conn.write_tls(&mut sock).is_err() {
                    break;
                }
            }
            return;
        }
        if let Some(mut early) = conn.early_data() {
            let mut tmp = [0u8; 4096];
            loop {
                match early.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() > MAX_EARLY_DATA_BYTES {
                            break; // bound 0-RTT data; head limit enforced below
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    // The name the client asked for in SNI, if any. `handle_request` refuses a
    // Host that disagrees with it, so a connection established for one vhost
    // cannot be used to fetch another's content under the first one's
    // certificate and security-header policy.
    let sni = conn.server_name().map(|s| s.to_ascii_lowercase());

    let max_transfer = (max_response_secs != 0).then(|| Duration::from_secs(max_response_secs));
    let phase = Phase::default();
    let mut dl = DeadlineIo::new(&mut sock, Instant::now(), max_transfer, phase.clone());
    let mut tls = Stream::new(&mut conn, &mut dl);
    // TLS: serve content.
    serve_over(&mut tls, &vhosts, buf, false, conn_deadline, &phase, sni.as_deref());
}

/// The hard deadline for whatever the connection is *currently* doing, shared
/// between `serve_over` — which knows the phase — and `DeadlineIo`, which sits
/// below rustls.
///
/// `serve_over` can only test its own deadlines *between* calls to
/// `stream.read()`, and `rustls::Stream::read` does not return until a whole TLS
/// record has been assembled: `prepare_read` loops `complete_io` for as long as
/// bytes keep trickling in, one socket read at a time. So a client that finishes
/// the handshake and then dribbles one byte at a time *inside* a record never
/// returns control to the head loop, and neither `HEADER_TIMEOUT_SECS` nor
/// `CONN_MAX_SECS` is ever consulted — on :443 they were decoration. (Measured
/// before this existed: a byte every 14s held a connection past 90s having sent
/// six bytes, bounded only by the ~16 KiB record cap at roughly 63 hours.) The
/// per-syscall socket timeout does not close it either: it only bounds one
/// `recv`, and any byte inside the window restarts the whole thing.
///
/// It is one `Rc<Cell<..>>` rather than a field on `DeadlineIo` because
/// `serve_over` only ever sees the `rustls::Stream` that mutably borrows the
/// `DeadlineIo` and cannot reach through it. One connection, one thread, so a
/// `Cell` is all the sharing that is needed.
#[derive(Clone, Default)]
struct Phase(Rc<Cell<Option<Instant>>>);

impl Phase {
    /// Bound the phase about to start: reading one request head.
    fn arm(&self, at: Instant) {
        self.0.set(Some(at));
    }
    /// A response is in flight. An absolute bound here would truncate a
    /// legitimately slow large download, so `DeadlineIo`'s minimum-rate check
    /// governs this phase instead.
    fn disarm(&self) {
        self.0.set(None);
    }
    fn get(&self) -> Option<Instant> {
        self.0.get()
    }
}

/// A socket that hard-fails when the connection stops making real progress.
///
/// The deadline has to be enforced at the socket, below rustls: a write timeout
/// surfaces as WouldBlock, which rustls reads as "blocked, not failed" and
/// retries, so a client that asks for a large asset and then stops reading pins
/// a connection slot, a thread and an fd. A real error here propagates straight
/// out of `complete_io` and the connection is torn down within one syscall.
///
/// Three bounds, each covering what the others cannot:
///   - `phase` — the hard, non-resetting deadline for the current request head
///     (see `Phase`). This is what makes the head timeout real on TLS.
///   - the progress window — a response must move `MIN_PROGRESS_BYTES` per
///     `PROGRESS_TIMEOUT_SECS`. A rate, not a liveness bit: "some byte moved"
///     is trivially satisfied by an attacker and says nothing about whether the
///     transfer is going anywhere. Checked on writes only; a read means the
///     connection is between responses, which is what the phase deadline and
///     the socket timeout are for, so a read rolls the window over instead.
///   - `deadline` — the operator's absolute `max_response_secs` cap, off by
///     default because it truncates a genuinely slow large download.
struct DeadlineIo<'a> {
    inner: &'a mut TcpStream,
    idle: Duration,
    /// Start of the current progress window, and the bytes written within it.
    window: Instant,
    moved: usize,
    deadline: Option<Instant>,
    phase: Phase,
}

impl<'a> DeadlineIo<'a> {
    fn new(
        inner: &'a mut TcpStream,
        now: Instant,
        max_transfer: Option<Duration>,
        phase: Phase,
    ) -> Self {
        DeadlineIo {
            inner,
            idle: Duration::from_secs(PROGRESS_TIMEOUT_SECS),
            window: now,
            moved: 0,
            deadline: max_transfer.map(|d| now + d),
            phase,
        }
    }
    fn check(&self) -> io::Result<()> {
        if self.deadline.is_some_and(|dl| Instant::now() >= dl) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "absolute transfer deadline"));
        }
        if self.phase.get().is_some_and(|dl| Instant::now() >= dl) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "request head deadline"));
        }
        Ok(())
    }
    /// The write-side bound: the response must clear `MIN_PROGRESS_BYTES` in
    /// every `idle` window, or the connection is dropped.
    ///
    /// The window is rolled over *here*, on the way in, rather than after a
    /// successful write. A stalled client's writes fail with WouldBlock, which
    /// rustls treats as "blocked, not failed" and retries — so a rollover that
    /// only ran on the success path would never run at all, and the window would
    /// keep reporting the large burst that filled the socket buffer at the start
    /// of the response as if it had just happened. The quota has to be re-earned
    /// every window, not earned once.
    fn check_rate(&mut self) -> io::Result<()> {
        if self.window.elapsed() >= self.idle {
            if self.moved < MIN_PROGRESS_BYTES {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "below minimum transfer rate"));
            }
            self.window = Instant::now();
            self.moved = 0;
        }
        Ok(())
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let n = self.inner.read(b)?;
        if n > 0 {
            // Between responses: start the next response's window clean rather
            // than judging it on a window an idle keep-alive gap has aged out.
            self.window = Instant::now();
            self.moved = 0;
        }
        Ok(n)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.check_rate()?;
        let n = self.inner.write(b)?;
        self.moved = self.moved.saturating_add(n);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        // flush moves no application bytes of its own; just honour the deadlines.
        self.check()?;
        self.check_rate()?;
        self.inner.flush()
    }
}

/// Drive one plain-HTTP connection (no TLS): every request 301s to HTTPS,
/// except the ACME challenge prefix, which must answer on :80.
fn handle_plain(mut sock: TcpStream, vhosts: Arc<Vhosts>, max_response_secs: u64) {
    let conn_deadline = Instant::now() + Duration::from_secs(CONN_MAX_SECS);
    let _ = sock.set_nodelay(true);
    let t = Some(Duration::from_secs(IO_TIMEOUT_SECS));
    let _ = sock.set_read_timeout(t);
    let _ = sock.set_write_timeout(t);
    let max_transfer = (max_response_secs != 0).then(|| Duration::from_secs(max_response_secs));
    let phase = Phase::default();
    let mut dl = DeadlineIo::new(&mut sock, Instant::now(), max_transfer, phase.clone());
    // No TLS here, so there is no SNI to bind the Host header against.
    serve_over(&mut dl, &vhosts, Vec::new(), true, conn_deadline, &phase, None);
}

/// The HTTP/1.1 keep-alive request loop over any byte stream — a plain TCP
/// socket or a rustls stream. `buf` may already hold bytes (e.g. 0-RTT data).
/// Pipelined bytes past one request head are preserved for the next iteration.
///
/// `conn_deadline` is the absolute end of this connection's life. The socket
/// timeouts are per-syscall and reset on every byte, so they alone cannot bound
/// a client that dribbles one byte at a time; these deadlines can — but only in
/// cooperation with `phase`, because on TLS a `stream.read()` may not return for
/// as long as a record keeps trickling in. See `Phase`.
///
/// `sni` is the name the TLS handshake asked for, or `None` on the plain
/// listener. When present, the request's `Host` must agree with it.
fn serve_over<S: Read + Write>(
    stream: &mut S,
    vhosts: &Vhosts,
    mut buf: Vec<u8>,
    redirect_https: bool,
    conn_deadline: Instant,
    phase: &Phase,
    sni: Option<&str>,
) {
    // The precomputed pre-parse error responses (431/408) sent here. They carry
    // the server-level header block: no site is known this early.
    let errs: &ErrorPages = &vhosts.errors;
    for reqs in 0..MAX_REQS_PER_CONN {
        if Instant::now() >= conn_deadline {
            return;
        }
        // Bound the head phase below rustls as well as in this loop. An idle
        // keep-alive connection is allowed to sit in the first read until the
        // socket timeout fires, and only once bytes arrive does
        // HEADER_TIMEOUT_SECS apply — so the ceiling handed down is the two of
        // them in sequence, never tighter than what this loop already permits.
        phase.arm(
            conn_deadline
                .min(Instant::now() + Duration::from_secs(IO_TIMEOUT_SECS + HEADER_TIMEOUT_SECS)),
        );
        // Accumulate until a full header block is present. The socket read
        // timeout covers idle time between keep-alive requests; `head_deadline`
        // starts only once bytes for THIS request begin arriving, so a browser
        // parking an idle connection is not punished for it.
        let mut head_start = if buf.is_empty() { None } else { Some(Instant::now()) };
        // How far into `buf` the terminator search has already run. Without it
        // each read rescans the whole buffer, which is O(n^2) against a client
        // feeding one byte at a time.
        let mut scanned = 0usize;
        let head_end = loop {
            let from = scanned.saturating_sub(3); // a CRLFCRLF may straddle reads
            if let Some(pos) = find(&buf[from..], b"\r\n\r\n") {
                let end = from + pos + 4;
                // `buf` can arrive pre-filled (0-RTT) or overshoot by one read
                // chunk, so the length check below is not enough on its own:
                // bound the head we actually found, or an oversized head slips
                // straight through to the parser.
                if end > MAX_HEADER_BYTES {
                    let _ =
                        send_error(stream, &errs.headers_too_large, false, false);
                    return;
                }
                break end;
            }
            scanned = buf.len();
            if buf.len() >= MAX_HEADER_BYTES {
                let _ = send_error(stream, &errs.headers_too_large, false, false);
                return;
            }
            let expired = head_start
                .map(|t0| t0.elapsed() >= Duration::from_secs(HEADER_TIMEOUT_SECS))
                .unwrap_or(false);
            if expired || Instant::now() >= conn_deadline {
                let _ = send_error(stream, &errs.request_timeout, false, false);
                return;
            }
            let mut tmp = [0u8; 4096];
            match stream.read(&mut tmp) {
                Ok(0) => return, // clean close
                Ok(n) => {
                    if head_start.is_none() {
                        head_start = Some(Instant::now());
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                Err(_) => return, // timeout / error
            }
        };

        // The head is in; a response is about to go out. Hand the write phase to
        // DeadlineIo's minimum-rate check, which does not truncate a legitimately
        // slow large download the way an absolute deadline would.
        phase.disarm();

        let want_ka = reqs + 1 < MAX_REQS_PER_CONN;
        match handle_request(stream, &buf[..head_end], vhosts, want_ka, redirect_https, sni) {
            Ok(true) => {}
            Ok(false) | Err(_) => return,
        }
        buf.drain(..head_end);
    }
}

// ------------------------------------------------------------------- TLS

/// Reject a cert and a key that are not two halves of the same pair.
///
/// Nothing else on the load path catches this: both files parse, the key type
/// is supported, and the SAN check inside `resolver.add` only looks at the
/// certificate. So a copy-pasted key path (or a renewal that rewrites
/// privkey.pem while fullchain.pem is stale) reloads "successfully" and then
/// fails the signature in every single handshake — the vhost is 100% down with
/// a "config reloaded" line in the log and the working runtime already gone.
/// `Unknown` means the key type does not expose an SPKI we can compare; that is
/// not evidence of a mismatch, so it must still load.
fn check_pair(
    certs: &[rustls::pki_types::CertificateDer<'static>],
    signing_key: &Arc<dyn rustls::sign::SigningKey>,
    label: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<(), String> {
    let ck = rustls::sign::CertifiedKey::new(certs.to_vec(), Arc::clone(signing_key));
    match ck.keys_match() {
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => Ok(()),
        Err(e) => Err(format!("{label}: key {key_path} does not match cert {cert_path}: {e}")),
    }
}

fn build_tls(cfg: &Config) -> Result<Arc<ServerConfig>, String> {
    // One SNI resolver mapping each site's domain to its own cert+key, so a
    // client is only offered a certificate for a configured host — unknown
    // domains fail the handshake (host allowlist enforced at the TLS layer too).
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    for s in &cfg.sites {
        let label = s.hosts.join(",");
        let cert_file = fs::File::open(&s.cert)
            .map_err(|e| format!("{label}: cannot open cert {}: {e}", s.cert))?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{label}: cannot parse cert: {e}"))?;
        if certs.is_empty() {
            return Err(format!("{label}: no certificates in {}", s.cert));
        }
        let key_file = fs::File::open(&s.key)
            .map_err(|e| format!("{label}: cannot open key {}: {e}", s.key))?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
            .map_err(|e| format!("{label}: cannot read key: {e}"))?
            .ok_or_else(|| format!("{label}: no private key in {}", s.key))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|_| format!("{label}: unsupported key type"))?;
        check_pair(&certs, &signing_key, &label, &s.cert, &s.key)?;
        // Register the same cert under every name this site answers to. rustls
        // verifies the certificate actually covers each name, so a missing SAN
        // fails the (re)load loudly instead of serving a mismatched cert.
        for host in &s.hosts {
            let ck = rustls::sign::CertifiedKey::new(certs.clone(), Arc::clone(&signing_key));
            resolver.add(host, ck).map_err(|e| {
                format!("{host}: sni add failed (cert {} must cover this name): {e}", s.cert)
            })?;
        }
    }

    // Redirect-only hosts need no separate pass: they are ordinary sites (just
    // without a root), so the loop above already registered their certificates —
    // which they do need, since the handshake must complete before the 301.

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions() // TLS 1.2 + 1.3
        .map_err(|e| format!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    // Session resumption: a resumed TLS 1.3 handshake skips the certificate and
    // signature, collapsing to ~1-RTT — the cheap reconnect the profiling showed
    // we need (a full handshake was ~2.5 ms).
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(4096);

    // 0-RTT early data: a resuming client may send its request in the very first
    // flight, saving a further round trip. Bounded to MAX_EARLY_DATA_BYTES.
    // SECURITY: 0-RTT data is replayable by a network attacker. That is safe
    // here because we only serve idempotent, side-effect-free GET/HEAD of static
    // public files — a replayed request just re-fetches a public asset.
    config.max_early_data_size = MAX_EARLY_DATA_BYTES as u32;

    Ok(Arc::new(config))
}

// ------------------------------------------------- swappable runtime state

/// Everything derived from the config file that can be replaced at runtime:
/// the virtual-host map and the TLS config (whose SNI resolver holds each
/// site's certificate). Swapped as one unit so sites and certs never disagree.
struct Runtime {
    vhosts: Arc<Vhosts>,
    tls: Arc<ServerConfig>,
}
type SharedRuntime = Arc<RwLock<Arc<Runtime>>>;

/// Resolve one site's config into the `Policy` its cache is built with and its
/// responses carry. Each site gets its own because a `site` block may override
/// any of the cache, compression and header settings.
fn site_policy(cfg: &Config, s: &config::SiteConfig) -> cache::Policy {
    cache::Policy::with_headers(
        s.tuning,
        &s.headers,
        cfg.storage,
        std::path::PathBuf::from(cfg.disk_cache.clone().unwrap_or_default()),
    )
}

/// Load every site's document root into a fresh cache. A site with no root is a
/// redirect-only host: it still gets a `Site` (and a certificate), just an empty
/// cache, and nothing on the serve path has to know the difference.
fn build_vhosts(cfg: &Config) -> Result<Vhosts, String> {
    let mut sites: Sites = HashMap::new();
    let mut total = 0usize; // one budget shared by every site, not per-site
    // The precomputed error responses are retained buffers like any other, and
    // `max_total_bytes` is documented as counting every retained byte, so they
    // are charged before the first root is walked. A few kilobytes per site
    // against a 2 GiB default: small, but not silently uncounted.
    let server_errors = ErrorPages::new(&cfg.headers.render());
    total += server_errors.retained_bytes();
    for s in &cfg.sites {
        let label = s.hosts.join(",");
        let policy = Arc::new(site_policy(cfg, s));
        let one_set = policy.errors.retained_bytes();
        total += one_set;
        // The ceiling is enforced here, not only inside the content walk. `walk`
        // skips the budget under Disk storage (it holds no bodies in RAM) and
        // never runs at all for a redirect-only site, but these buffers are
        // resident in every mode and for every site. The message separates this
        // site's error bytes from the running total, because the total also
        // holds the server error set and the content of the earlier sites: the
        // named site is the one that crossed the line, not always the one that
        // spent the memory. Every site carries the same value: a site block
        // cannot override `max_total_bytes`.
        let budget = policy.t.max_total_bytes;
        if total > budget {
            return Err(format!(
                "site {label}: max_total_bytes ({budget}) is too small: {total} bytes are \
                 retained through this site, {one_set} of them by this site's precomputed \
                 error responses. The rest is the server error set and the content of the \
                 sites before this one"
            ));
        }
        let (root, site_cache) = match &s.root {
            Some(r) => {
                let root = fs::canonicalize(r)
                    .map_err(|e| format!("site {label}: root {r} unusable: {e}"))?;
                if !root.is_dir() {
                    return Err(format!("site {label}: root {r} is not a directory"));
                }
                let before = total;
                let c = build_cache(&root, &mut total, &policy).ok_or_else(|| {
                    format!(
                        "site {label}: root {r} unreadable, or its content takes the cache over \
                         max_total_bytes ({budget}, of which {before} bytes were already retained)"
                    )
                })?;
                eprintln!(
                    "bare-server: site {label} -> cached {} files ({} bytes) from {}",
                    c.map.len(),
                    total - before,
                    root.display()
                );
                (Some(root), c)
            }
            None => {
                eprintln!("bare-server: site {label} -> redirect only (no root)");
                (None, cache::SiteCache::empty())
            }
        };
        // One Site, shared by every alias: the content is compressed once and
        // held once, and a hot reload swaps the cache for all names at once.
        let site = Arc::new(Site {
            root,
            cache: RwLock::new(Arc::new(site_cache)),
            force_ssl: s.force_ssl,
            canonical_urls: s.canonical_urls,
            redirects: s.redirects.clone(),
            policy,
        });
        for host in &s.hosts {
            if sites.insert(host.clone(), Arc::clone(&site)).is_some() {
                return Err(format!("duplicate host across sites: {host}"));
            }
        }
    }
    Ok(Vhosts {
        sites,
        https_port: cfg.port.clone(),
        http_port: cfg.http_port.clone(),
        // Server-level headers, baked into the responses that go out before a
        // site is known.
        errors: server_errors,
    })
}

/// Resident bytes the vhost table holds outside the content caches: the
/// server-level precomputed error responses, plus one set per distinct site.
/// Deduped by `Site` identity, because every alias of a site shares one `Site`
/// and therefore one policy and one set of buffers.
fn error_page_bytes(vhosts: &Vhosts) -> usize {
    let mut seen = std::collections::HashSet::new();
    let per_site: usize = vhosts
        .sites
        .values()
        .filter(|s| seen.insert(Arc::as_ptr(s) as usize))
        .map(|s| s.policy.errors.retained_bytes())
        .sum();
    vhosts.errors.retained_bytes() + per_site
}

/// Build both halves of the runtime. TLS is built first so a bad cert aborts
/// the reload before we spend time compressing site content.
fn build_runtime(cfg: &Config) -> Result<Runtime, String> {
    let tls = build_tls(cfg)?;
    let vhosts = Arc::new(build_vhosts(cfg)?);
    Ok(Runtime { vhosts, tls })
}

// ------------------------------------------------------- listener lifecycle

/// A running accept loop. `gen` is bumped to retire it: the loop re-checks the
/// counter after every accept and exits when it no longer matches, dropping the
/// listener (and closing its socket) with it.
struct ListenerCtl {
    addr: String,
    gen: Arc<AtomicUsize>,
    sem: Arc<Semaphore>,
    peer: Arc<PeerLimiter>,
    /// Shared with every accept loop and re-read per connection, so
    /// `max_response_secs` takes effect on reload without a restart.
    response_secs: Arc<AtomicU64>,
    tls: bool,
    label: &'static str,
}

/// Spawn an accept loop for `listener`, tagged with `generation`.
fn spawn_accept(
    listener: Arc<TcpListener>,
    generation: usize,
    gen_ctr: Arc<AtomicUsize>,
    sem: Arc<Semaphore>,
    peer: Arc<PeerLimiter>,
    response_secs: Arc<AtomicU64>,
    shared: SharedRuntime,
    tls: bool,
) {
    let label = if tls { "HTTPS" } else { "HTTP" };
    thread::spawn(move || {
        let mut last_log: Option<Instant> = None;
        let mut last_spawn_log: Option<Instant> = None;
        loop {
            // Wait for a slot, but wake periodically to notice retirement: while
            // every permit is held this loop would otherwise never reach the
            // generation check below, so a listener the operator "stopped" would
            // keep its socket bound for as long as the saturation lasted.
            let permit = loop {
                if gen_ctr.load(Ordering::Relaxed) != generation {
                    return;
                }
                if let Some(p) = sem.acquire_timeout(Duration::from_millis(500)) {
                    break p;
                }
            };
            let sock = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) => {
                    if gen_ctr.load(Ordering::Relaxed) != generation {
                        return;
                    }
                    match e.kind() {
                        // These dequeue (or never queued) the pending
                        // connection, so retrying immediately makes progress.
                        io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted => continue,
                        // EMFILE/ENFILE/ENOBUFS leave the connection queued, so
                        // the next accept() fails identically and instantly.
                        // Without a backoff that is a silent 100% CPU spin that
                        // starves the very workers whose timeouts would free the
                        // descriptors — a state that sustains itself until the
                        // process is restarted. Log it, but at most once a
                        // second: a sustained EMFILE would otherwise flood the
                        // journal as fast as it spins.
                        _ => {
                            drop(permit); // don't hold a slot while sleeping
                            if last_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                                eprintln!("bare-server: accept on {label}: {e}");
                                last_log = Some(Instant::now());
                            }
                            thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                    }
                }
            };
            // Retired while we were blocked in accept(): this is almost always
            // our own wake-up probe, so drop it and let the replacement serve.
            if gen_ctr.load(Ordering::Relaxed) != generation {
                return;
            }
            // Per-source-IP cap: one peer must not hold every global slot. If it
            // is already at its cap, drop this connection now (releasing the
            // global permit with it) rather than spending a thread on it. A peer
            // whose address cannot be read is not blocked.
            let peer_permit = match sock.peer_addr() {
                Ok(a) => match peer.try_acquire(a.ip()) {
                    Some(p) => p,
                    None => {
                        drop(sock); // over the per-IP cap; permit freed on continue
                        continue;
                    }
                },
                // No address, no accounting — so fail closed rather than hand out
                // an unmetered slot. In practice this is a peer that has already
                // reset the connection, so there is nothing to serve anyway; the
                // alternative is a rate-limiting control with a bypass in it.
                Err(_) => {
                    drop(sock);
                    continue;
                }
            };
            // Read the current runtime per connection, so a config reload is
            // picked up by the next connection without a restart.
            let rt = current(&shared);
            let vhosts = Arc::clone(&rt.vhosts);
            let tls_cfg = Arc::clone(&rt.tls);
            // Re-read per connection for the same reason as the runtime above:
            // a reloaded `max_response_secs` must bind the next connection.
            let response_secs = response_secs.load(Ordering::Relaxed);
            // A failed spawn (ENOMEM on the stack mapping under a cgroup memory
            // ceiling, EAGAIN against a thread limit) drops the closure, which
            // releases the permit and closes the socket: the client sees an
            // empty reply while the process stays up and every liveness probe
            // reads healthy. Log it, at most once a second so a sustained
            // failure does not flood the journal as fast as clients connect.
            if let Err(e) = thread::Builder::new()
                .stack_size(THREAD_STACK_BYTES)
                .spawn(move || {
                    let _permit = permit; // released on thread exit (even on panic)
                    let _peer_permit = peer_permit; // ditto for the per-IP slot
                    if tls {
                        handle_connection(sock, tls_cfg, vhosts, response_secs);
                    } else {
                        handle_plain(sock, vhosts, response_secs);
                    }
                })
            {
                if last_spawn_log.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                    eprintln!("bare-server: cannot spawn worker for {label}: {e}");
                    last_spawn_log = Some(Instant::now());
                }
                // Same backoff as the accept-error arm: a sustained ENOMEM/EAGAIN
                // would otherwise accept-and-drop at 100% CPU, starving the very
                // workers whose exit would free the memory or thread slots.
                thread::sleep(Duration::from_millis(50));
            }
        }
    });
}

/// Retire an accept loop: bump its generation, then unblock its `accept()` with
/// a throwaway local connection so it notices and exits promptly.
fn retire(ctl: &ListenerCtl) {
    ctl.gen.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut addrs) = ctl.addr.to_socket_addrs() {
        if let Some(a) = addrs.next() {
            let _ = TcpStream::connect_timeout(&a, Duration::from_millis(500));
        }
    }
}

/// Move a listener to `new_addr`. The new socket is bound BEFORE the old loop is
/// retired, so if the bind fails (port busy, no permission) the existing
/// listener keeps serving. The error is returned rather than logged so the
/// caller can retry it and log it once instead of once per attempt.
fn rebind(ctl: &mut ListenerCtl, new_addr: &str, shared: &SharedRuntime) -> Result<(), String> {
    if ctl.addr == new_addr {
        return Ok(());
    }
    let listener = match TcpListener::bind(new_addr) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            return Err(format!(
                "cannot rebind {} to {new_addr}: {e}; staying on {}",
                ctl.label, ctl.addr
            ));
        }
    };
    retire(ctl);
    let gen = Arc::new(AtomicUsize::new(0));
    spawn_accept(
        listener,
        0,
        Arc::clone(&gen),
        Arc::clone(&ctl.sem),
        Arc::clone(&ctl.peer),
        Arc::clone(&ctl.response_secs),
        Arc::clone(shared),
        ctl.tls,
    );
    eprintln!("bare-server: {} rebound {} -> {new_addr}", ctl.label, ctl.addr);
    ctl.addr = new_addr.to_string();
    ctl.gen = gen;
    Ok(())
}

/// Start a listener from scratch (used when `listen_http` is added at runtime).
fn start_listener(
    addr: &str,
    max_conns: usize,
    max_conns_per_ip: usize,
    response_secs: Arc<AtomicU64>,
    tls: bool,
    label: &'static str,
    shared: &SharedRuntime,
) -> Result<ListenerCtl, String> {
    let listener = match TcpListener::bind(addr) {
        Ok(l) => Arc::new(l),
        Err(e) => return Err(format!("cannot bind {label} on {addr}: {e}")),
    };
    let gen = Arc::new(AtomicUsize::new(0));
    let sem = Semaphore::new(max_conns);
    let peer = PeerLimiter::new(max_conns_per_ip);
    spawn_accept(
        listener,
        0,
        Arc::clone(&gen),
        Arc::clone(&sem),
        Arc::clone(&peer),
        Arc::clone(&response_secs),
        Arc::clone(shared),
        tls,
    );
    Ok(ListenerCtl { addr: addr.to_string(), gen, sem, peer, response_secs, tls, label })
}

fn current(shared: &SharedRuntime) -> Arc<Runtime> {
    Arc::clone(&shared.read().unwrap_or_else(std::sync::PoisonError::into_inner))
}

// ------------------------------------------------------------------- main

fn main() {
    // Flags are deliberately few: this takes a config file and runs. `--quiet`
    // exists only to silence the boot banner, `--version` to identify a binary.
    let mut quiet = false;
    let mut config_path: Option<String> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("{}", banner::one_line());
                return;
            }
            "--help" | "-h" => {
                println!("usage: bare-server [--quiet] <config-file>");
                return;
            }
            "--quiet" | "-q" => quiet = true,
            _ if arg.starts_with('-') => fatal(&format!("unknown option: {arg}")),
            _ if config_path.is_some() => fatal("usage: bare-server [--quiet] <config-file>"),
            _ => config_path = Some(arg),
        }
    }
    let Some(config_path) = config_path else {
        fatal("usage: bare-server [--quiet] <config-file>");
    };
    // No "config:" prefix here: parse errors already name the offending line,
    // and the multi-line hints read badly behind a second label.
    let cfg = load_config(&config_path).unwrap_or_else(|e| fatal(&e));

    // Before any work, but after the config parses — the banner reports the
    // settings that were actually loaded, so it must not print for a config
    // that turned out to be invalid.
    banner::print(quiet, cfg.storage, cfg.sites[0].tuning.brotli_quality, cfg.sites[0].tuning.compression);

    // Disk storage: make sure the cache directory exists (failing fast and
    // loudly if it cannot be created) and clear any snapshot left behind by a
    // previous run before we build our own into it.
    if cfg.storage == config::Storage::Disk {
        let dc = std::path::PathBuf::from(cfg.disk_cache.clone().unwrap_or_default());
        if let Err(e) = fs::create_dir_all(&dc) {
            fatal(&format!("disk_cache {}: {e}", dc.display()));
        }
        cache::clear_stale_builds(&dc);
        eprintln!("bare-server: disk storage — snapshotting content under {}", dc.display());
    }

    // Sample the watched inputs BEFORE building anything from them: a deploy
    // that is still rsyncing while we start must not be recorded as applied.
    let boot = sample(&config_path, &cfg);

    // Build the swappable runtime (sites + TLS certs) once at startup.
    let runtime: SharedRuntime = Arc::new(RwLock::new(Arc::new(
        build_runtime(&cfg).unwrap_or_else(|e| fatal(&e)),
    )));

    // Listeners run on their own threads so they can be retired and rebound
    // when `listen`/`listen_http` change. Separate semaphores per listener: one
    // shared cap would let cheap plain-HTTP connections consume every slot and
    // stall the HTTPS accept loop — taking the site down through the port that
    // only ever issues redirects.
    let per_ip = cfg.max_conns_per_ip;
    // One cell shared by both listeners and every accept loop, so a reloaded
    // `max_response_secs` reaches connections that have not been accepted yet.
    let response_secs = Arc::new(AtomicU64::new(cfg.max_response_secs));
    let https_addr = format!("{}:{}", cfg.host, cfg.port);
    let mut https = start_listener(
        &https_addr,
        MAX_CONNS,
        per_ip,
        Arc::clone(&response_secs),
        true,
        "HTTPS",
        &runtime,
    )
    .unwrap_or_else(|e| fatal(&e));
    eprintln!("bare-server: listening on {https_addr}");

    let mut http = if cfg.http_host.is_empty() {
        eprintln!("bare-server: no 'listen_http' — plain-HTTP listener disabled");
        None
    } else {
        let haddr = format!("{}:{}", cfg.http_host, cfg.http_port);
        let c = start_listener(
            &haddr,
            MAX_CONNS_HTTP,
            per_ip,
            Arc::clone(&response_secs),
            false,
            "HTTP",
            &runtime,
        )
        .unwrap_or_else(|e| fatal(&e));
        eprintln!("bare-server: also serving HTTP on {haddr}");
        Some(c)
    };

    eprintln!(
        "bare-server: watching {config_path} + site roots + certs (poll {WATCH_INTERVAL_SECS}s)"
    );
    // The watcher owns the main thread: it reloads sites, certs and listeners.
    watch(config_path, boot, runtime, &mut https, &mut http, per_ip, response_secs);
}

// ------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::io::{Read, Write};

    // ---- pure header/URL helpers ----

    #[test]
    fn find_locates_and_bounds() {
        assert_eq!(find(b"abcdef", b"cd"), Some(2));
        assert_eq!(find(b"abc", b"x"), None);
        assert_eq!(find(b"abc", b""), None); // empty needle
        assert_eq!(find(b"a", b"abc"), None); // needle longer than hay
    }

    #[test]
    fn zero_q_detection() {
        for y in ["0", "0.", "0.0", "0.000"] {
            assert!(is_zero_q(y), "{y} is q=0");
        }
        for n in ["1", "0.5", "0.001", "0.1", ""] {
            assert!(!is_zero_q(n), "{n} is not q=0");
        }
    }

    #[test]
    fn accept_encoding_parsing() {
        assert!(accepts_encoding("gzip, br", "br"));
        assert!(accepts_encoding("gzip, deflate, br", "gzip"));
        assert!(!accepts_encoding("gzip", "br"));
        assert!(!accepts_encoding("", "gzip")); // absent header: identity only
        assert!(!accepts_encoding("br;q=0", "br")); // explicit refusal
        assert!(accepts_encoding("br;q=0.1", "br"));
        assert!(accepts_encoding("*", "br")); // wildcard accepts
        assert!(!accepts_encoding("*;q=0", "br")); // wildcard refusal
        assert!(!accepts_encoding("*, br;q=0", "br")); // explicit beats wildcard
        // A multi-byte char after the coding name must not panic (get(..2)).
        assert!(accepts_encoding("gzip;\u{20ac}", "gzip"));
    }

    #[test]
    fn if_none_match_uses_whole_tag_comparison() {
        assert!(inm_matches("\"abc-123\"", "abc-123"));
        assert!(inm_matches("*", "anything"));
        assert!(inm_matches("W/\"abc-123\"", "abc-123")); // weak prefix stripped
        assert!(inm_matches("\"x\", \"abc-123\"", "abc-123")); // in a list
        assert!(!inm_matches("\"abc-1234\"", "abc-123")); // no substring match
        assert!(!inm_matches("\"other\"", "abc-123"));
    }

    #[test]
    fn hex_and_percent_decoding() {
        assert_eq!(hexval(b'0'), Some(0));
        assert_eq!(hexval(b'f'), Some(15));
        assert_eq!(hexval(b'F'), Some(15));
        assert_eq!(hexval(b'g'), None);
        assert_eq!(percent_decode("/a%20b").unwrap(), b"/a b");
        assert_eq!(percent_decode("/%69ndex").unwrap(), b"/index");
        assert!(percent_decode("/%00").is_none()); // NUL rejected
        assert!(percent_decode("/%zz").is_none()); // bad hex
        assert!(percent_decode("/%2").is_none()); // truncated escape
        assert!(percent_decode("/a\u{7f}").is_none()); // DEL rejected
    }

    #[test]
    fn host_normalization() {
        assert_eq!(normalize_host("Example.COM"), "example.com");
        assert_eq!(normalize_host("example.com:8443"), "example.com");
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(normalize_host("  host  "), "host");
    }

    // ---- resolve() ----

    #[test]
    fn resolve_direct_clean_and_dirindex() {
        let dir = TempDir::new();
        dir.write("index.html", b"home");
        dir.write("about.html", b"about");
        dir.write("blog/index.html", b"blog");
        let mut total = 0usize;
        let cache = cache::build_cache(dir.path(), &mut total, &cache::Policy::new(Default::default())).unwrap().map;

        assert!(matches!(resolve(&cache, "/about.html"), Some(Resolved::Entry(_))));
        assert!(matches!(resolve(&cache, "/about"), Some(Resolved::Entry(_)))); // clean URL
        assert!(matches!(resolve(&cache, "/"), Some(Resolved::Entry(_)))); // index
        assert!(matches!(resolve(&cache, "/blog/"), Some(Resolved::Entry(_)))); // dir index served
        assert!(matches!(resolve(&cache, "/blog"), Some(Resolved::DirIndex))); // needs trailing slash
        assert!(resolve(&cache, "/missing").is_none());
    }

    // ---- request/response integration over a mock stream ----

    struct MockStream {
        input: Vec<u8>,
        pos: usize,
        output: Vec<u8>,
        /// How many `write` calls the response took. Under TLS each one is a
        /// separate record and a separate `complete_io`, so the count is the
        /// contract `Variant` and `StatusResponse` exist to hold at one.
        writes: usize,
    }
    impl MockStream {
        fn new(input: &[u8]) -> Self {
            MockStream { input: input.to_vec(), pos: 0, output: Vec::new(), writes: 0 }
        }
    }
    impl Read for MockStream {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.input.len() - self.pos).min(b.len());
            b[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n) // Ok(0) at exhaustion == clean close
        }
    }
    impl Write for MockStream {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            self.writes += 1;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A vhost table with one content site, populated from real files on disk.
    /// Returns the TempDir too: it must outlive the vhosts (Site.root points at it).
    fn fixture(host: &str) -> (TempDir, Vhosts) {
        fixture_with(host, false)
    }

    /// As `fixture`, but lets a test pick the site's `force_ssl` setting.
    fn fixture_with(host: &str, force_ssl: bool) -> (TempDir, Vhosts) {
        fixture_tuned(host, force_ssl, Default::default())
    }

    /// As `fixture_with`, but built under a specific `Tuning`.
    fn fixture_tuned(
        host: &str,
        force_ssl: bool,
        tuning: crate::config::Tuning,
    ) -> (TempDir, Vhosts) {
        fixture_full(host, force_ssl, tuning, Default::default())
    }

    /// As `fixture_tuned`, but with a redirect rule set for the site.
    fn fixture_redirects(host: &str, redirects: crate::config::Redirects) -> (TempDir, Vhosts) {
        fixture_full(host, false, Default::default(), redirects)
    }

    /// A fixture with `canonical_urls = on`, optionally with explicit rules too.
    fn fixture_canonical(host: &str, redirects: crate::config::Redirects) -> (TempDir, Vhosts) {
        let (d, mut v) = fixture_full(host, false, Default::default(), redirects);
        let site = v.sites.get_mut(host).unwrap();
        let old = Arc::clone(site);
        *site = Arc::new(Site {
            root: old.root.clone(),
            cache: RwLock::new(Arc::new(cache::SiteCache::empty())),
            force_ssl: old.force_ssl,
            canonical_urls: true,
            redirects: old.redirects.clone(),
            policy: Arc::clone(&old.policy),
        });
        (d, v)
    }

    fn fixture_full(
        host: &str,
        force_ssl: bool,
        tuning: crate::config::Tuning,
        redirects: crate::config::Redirects,
    ) -> (TempDir, Vhosts) {
        let dir = TempDir::new();
        dir.write("index.html", b"<h1>home</h1>");
        dir.write("about.html", b"<h1>about</h1>");
        dir.write("blog/index.html", b"<h1>blog</h1>");
        // Compressible and comfortably over the 64-byte floor.
        dir.write("style.css", "body { color: red; }\n".repeat(20).as_bytes());
        let mut total = 0usize;
        let policy = Arc::new(cache::Policy::new(tuning));
        let cache = cache::build_cache(dir.path(), &mut total, &policy).unwrap();
        let site = Arc::new(Site {
            root: Some(dir.path().to_path_buf()),
            cache: RwLock::new(Arc::new(cache)),
            force_ssl,
            canonical_urls: false,
            redirects,
            policy,
        });
        let mut sites = HashMap::new();
        sites.insert(host.to_string(), site);
        let hdrs = crate::config::HeaderConfig::default().render();
        (
            dir,
            Vhosts {
                sites,
                https_port: "443".into(),
                http_port: "80".into(),
                errors: ErrorPages::new(&hdrs),
            },
        )
    }

    /// The rule set a `site` block's `redirect` lines would produce, built by
    /// running them through the real parser so the tests exercise the same path
    /// production does.
    fn rules(lines: &str) -> crate::config::Redirects {
        let text = format!(
            "listen = h:443\nsite a.com {{\n root = /w\n cert = /c\n key = /k\n{lines}\n}}\n"
        );
        let mut c = crate::config::parse_config(&text).expect("rules parse");
        std::mem::take(&mut c.sites[0].redirects)
    }

    fn run(vhosts: &Vhosts, raw: &str, want_ka: bool, redirect_https: bool) -> (bool, String) {
        let mut s = MockStream::new(b"");
        let ka =
            handle_request(&mut s, raw.as_bytes(), vhosts, want_ka, redirect_https, None).unwrap();
        (ka, String::from_utf8_lossy(&s.output).into_owned())
    }

    /// As `run`, but also reports how many `write` calls the response took.
    fn run_writes(vhosts: &Vhosts, raw: &str) -> (String, usize) {
        let mut s = MockStream::new(b"");
        handle_request(&mut s, raw.as_bytes(), vhosts, true, false, None).unwrap();
        (String::from_utf8_lossy(&s.output).into_owned(), s.writes)
    }

    fn header(resp: &str, name: &str) -> Option<String> {
        resp.split("\r\n")
            .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
    }

    #[test]
    fn get_index_returns_200_with_body_and_type() {
        let (_d, v) = fixture("example.com");
        let (ka, r) = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert_eq!(header(&r, "Content-Type:").as_deref(), Some("text/html; charset=utf-8"));
        assert!(r.ends_with("<h1>home</h1>"));
        assert!(ka, "HTTP/1.1 keeps alive by default");
    }

    #[test]
    fn head_returns_headers_without_body() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(r.contains("Content-Length: 13\r\n")); // length still advertised
        // Nothing follows the header terminator.
        assert_eq!(r.split("\r\n\r\n").nth(1), Some(""));
    }

    #[test]
    fn missing_file_is_404() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "GET /nope HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn an_error_response_is_one_write() {
        // Why the responses are precomputed. `rustls::Stream::write` runs
        // complete_io after every write, so a head-then-body error costs two
        // encrypt-and-socket round trips where a cache hit costs one.
        let (_d, v) = fixture("example.com");
        for req in [
            "GET /nope HTTP/1.1\r\nHost: example.com\r\n\r\n",                     // 404
            "HEAD /nope HTTP/1.1\r\nHost: example.com\r\n\r\n",                    // 404, no body
            "GET /nope HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", // 404, close
            "DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n",                      // 405
            "GET /a\u{01}b HTTP/1.1\r\nHost: example.com\r\n\r\n",                 // 400
            "GET / HTTP/1.1\r\nHost: other.com\r\n\r\n",                           // 404, no site
        ] {
            let (r, writes) = run_writes(&v, req);
            assert_eq!(writes, 1, "{req} took {writes} writes: {r}");
        }
    }

    #[test]
    fn an_error_is_never_stored_by_a_cache() {
        // With no Cache-Control a 404 is heuristically cacheable, so a shared
        // cache could keep answering 404 for a URL the site later publishes.
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "GET /nope HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert_eq!(header(&r, "Cache-Control:").as_deref(), Some("no-store"), "{r}");
    }

    #[test]
    fn head_on_an_error_sends_the_header_alone() {
        let (_d, v) = fixture("example.com");
        let (_k1, get) = run(&v, "GET /nope HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        let (_k2, head) = run(&v, "HEAD /nope HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        let (get_head, get_body) = get.split_once("\r\n\r\n").expect("header terminator");
        assert_eq!(head, format!("{get_head}\r\n\r\n"), "HEAD sends the GET header, nothing more");
        assert!(!get_body.is_empty(), "a GET error carries a body");
        // The real length stays advertised on a HEAD (RFC 9110 9.3.2).
        assert_eq!(header(&head, "Content-Length:"), Some(get_body.len().to_string()));
    }

    #[test]
    fn an_error_states_the_connection_it_leaves_behind() {
        let (_d, v) = fixture("example.com");
        let (ka, r) = run(&v, "GET /nope HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(ka, "a 404 does not have to close the connection");
        assert_eq!(header(&r, "Connection:").as_deref(), Some("keep-alive"), "{r}");
        let raw = "GET /nope HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let (ka, r) = run(&v, raw, true, false);
        assert!(!ka);
        assert_eq!(header(&r, "Connection:").as_deref(), Some("close"), "{r}");
    }

    #[test]
    fn unknown_or_absent_host_is_404() {
        let (_d, v) = fixture("example.com");
        let (_k1, r1) = run(&v, "GET / HTTP/1.1\r\nHost: other.com\r\n\r\n", true, false);
        assert!(r1.starts_with("HTTP/1.1 404"));
        let (_k2, r2) = run(&v, "GET / HTTP/1.1\r\n\r\n", true, false); // no Host
        assert!(r2.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn non_get_head_is_405() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        // The refusal has to tell the client what it may send instead.
        assert_eq!(header(&r, "Allow:").as_deref(), Some("GET, HEAD"));
    }

    #[test]
    fn control_byte_in_target_is_400() {
        let (_d, v) = fixture("example.com");
        let (ka, r) = run(&v, "GET /a\u{01}b HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(!ka, "a malformed request closes the connection");
    }

    #[test]
    fn absolute_form_target_is_400() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "GET http://x/ HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn a_declared_body_is_refused_but_content_length_zero_is_fine() {
        let (_d, v) = fixture("example.com");
        let (ka, r) = run(
            &v,
            "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n",
            true,
            false,
        );
        assert!(r.starts_with("HTTP/1.1 400"), "CL>0 desync risk -> 400");
        assert!(!ka, "must close so the undrained body is discarded");

        let (_ka2, r2) = run(
            &v,
            "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
            true,
            false,
        );
        assert!(r2.starts_with("HTTP/1.1 200"), "CL:0 is a real bodyless request");
    }

    #[test]
    fn transfer_encoding_is_refused() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(
            &v,
            "GET / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
            true,
            false,
        );
        assert!(r.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn non_utf8_head_is_400() {
        let (_d, v) = fixture("example.com");
        let mut s = MockStream::new(b"");
        let ka = handle_request(&mut s, &[0xff, 0xfe, b' '], &v, true, false, None).unwrap();
        assert!(String::from_utf8_lossy(&s.output).starts_with("HTTP/1.1 400"));
        assert!(!ka);
    }

    #[test]
    fn content_negotiation_selects_encoding() {
        let (_d, v) = fixture("example.com");
        let br = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br\r\n\r\n", true, false).1;
        assert_eq!(header(&br, "Content-Encoding:").as_deref(), Some("br"));
        assert_eq!(header(&br, "Vary:").as_deref(), Some("Accept-Encoding"));

        let gz = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n", true, false).1;
        assert_eq!(header(&gz, "Content-Encoding:").as_deref(), Some("gzip"));

        let id = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(header(&id, "Content-Encoding:").is_none(), "no AE header -> identity");

        let refused = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br;q=0, gzip\r\n\r\n", true, false).1;
        assert_eq!(header(&refused, "Content-Encoding:").as_deref(), Some("gzip"));
    }

    #[test]
    fn conditional_get_returns_304() {
        let (_d, v) = fixture("example.com");
        let r1 = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        let etag = header(&r1, "ETag:").unwrap();
        let raw = format!("GET /style.css HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\n\r\n");
        let r2 = run(&v, &raw, true, false).1;
        assert!(r2.starts_with("HTTP/1.1 304 Not Modified\r\n"), "{r2}");
        assert!(header(&r2, "Cache-Control:").is_some(), "304 must carry Cache-Control");
        assert_eq!(r2.split("\r\n\r\n").nth(1), Some("")); // no body
    }

    #[test]
    fn clean_url_directory_redirects_to_trailing_slash() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "GET /blog HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"));
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/blog/"));
    }

    #[test]
    fn plain_listener_serves_content_when_force_ssl_is_off() {
        // Default (no force_ssl): :80 serves the same content as :443 rather
        // than upgrading. `redirect_https = true` simulates the :80 listener.
        let (_d, v) = fixture_with("example.com", false);
        let (_ka, r) = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true);
        assert!(r.starts_with("HTTP/1.1 200"), "expected content over plain HTTP: {r}");
        assert_eq!(header(&r, "Content-Type:").as_deref(), Some("text/css; charset=utf-8"));
    }

    #[test]
    fn plain_listener_redirects_when_force_ssl_is_on_but_keeps_acme_plain() {
        let (_d, v) = fixture_with("example.com", true);
        let (_k1, r1) = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true);
        assert!(r1.starts_with("HTTP/1.1 301"), "{r1}");
        assert_eq!(header(&r1, "Location:").as_deref(), Some("https://example.com/style.css"));

        // Even with force_ssl the ACME challenge must stay answerable on :80,
        // or http-01 renewal breaks. A 404 here (no token on disk) proves it
        // reached the ACME handler instead of being bounced to HTTPS.
        let (_k2, r2) = run(&v, "GET /.well-known/acme-challenge/x HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true);
        assert!(r2.starts_with("HTTP/1.1 404"), "ACME path must not 301: {r2}");
    }

    #[test]
    fn force_ssl_does_not_affect_the_tls_listener() {
        // On :443 (redirect_https = false) a force_ssl site serves normally —
        // the flag must not cause a redirect loop.
        let (_d, v) = fixture_with("example.com", true);
        let (_ka, r) = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200"), "force_ssl must not loop on HTTPS: {r}");
    }

    #[test]
    fn dir_index_redirect_preserves_the_plain_scheme_for_allow_http() {
        // On :80 an allow_http site's "/blog" -> "/blog/" canonicalisation must
        // stay on http:// (finding 3): silently upgrading it to https defeats the
        // opt-out. Over TLS the same request redirects to https.
        let (_d, v) = fixture_with("example.com", false);
        let (_k1, http) = run(&v, "GET /blog HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true);
        assert!(http.starts_with("HTTP/1.1 301"), "{http}");
        assert_eq!(header(&http, "Location:").as_deref(), Some("http://example.com/blog/"));
        let (_k2, https) = run(&v, "GET /blog HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert_eq!(header(&https, "Location:").as_deref(), Some("https://example.com/blog/"));
    }

    /// Build a disk-backed vhost table. Returns the doc-root and disk-cache
    /// TempDirs too — both must outlive the vhosts (the snapshot lives under the
    /// cache dir, and the entries point at it).
    fn disk_fixture(host: &str) -> (TempDir, TempDir, Vhosts) {
        let root = TempDir::new();
        root.write("index.html", b"<h1>home</h1>");
        root.write("style.css", "body { color: red; }\n".repeat(20).as_bytes());
        let cachedir = TempDir::new();
        let policy = cache::Policy::with_headers(
            Default::default(),
            &crate::config::HeaderConfig::default(),
            crate::config::Storage::Disk,
            cachedir.path().to_path_buf(),
        );
        let policy = Arc::new(policy);
        let sc = cache::build_cache(root.path(), &mut 0usize, &policy).expect("disk cache built");
        let site = Arc::new(Site {
            root: Some(root.path().to_path_buf()),
            cache: RwLock::new(Arc::new(sc)),
            force_ssl: false,
            canonical_urls: false,
            redirects: Default::default(),
            policy,
        });
        let mut sites = HashMap::new();
        sites.insert(host.to_string(), site);
        let hdrs = crate::config::HeaderConfig::default().render();
        let v = Vhosts {
            sites,
            https_port: "443".into(),
            http_port: "80".into(),
            errors: ErrorPages::new(&hdrs),
        };
        (root, cachedir, v)
    }

    #[test]
    fn disk_mode_streams_identity_and_serves_sidecars() {
        let css = "body { color: red; }\n".repeat(20);
        // `cachedir` is bound first so it outlives `v` (and the snapshot it owns).
        let (_root, _cachedir, v) = disk_fixture("example.com");

        // No Accept-Encoding: identity body streamed verbatim from disk.
        let (_ka, r) = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert!(r.contains(&format!("Content-Length: {}\r\n", css.len())), "{r}");
        assert!(!r.contains("Content-Encoding"), "identity carries no encoding: {r}");
        assert!(r.ends_with(&css), "disk identity body must match the source file");

        // Accept-Encoding: gzip -> the precompressed .gz sidecar.
        let (_k2, rg) = run(
            &v,
            "GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: gzip\r\n\r\n",
            true,
            false,
        );
        assert_eq!(header(&rg, "Content-Encoding:").as_deref(), Some("gzip"));
        assert_eq!(header(&rg, "Vary:").as_deref(), Some("Accept-Encoding"));

        // HEAD: header (with the real Content-Length) but no streamed body.
        let (_k3, rh) = run(&v, "HEAD /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(rh.contains(&format!("Content-Length: {}\r\n", css.len())));
        assert_eq!(rh.split("\r\n\r\n").nth(1), Some(""), "HEAD must carry no body");
    }

    #[test]
    fn disk_mode_conditional_get_and_close() {
        let (_root, _cachedir, v) = disk_fixture("example.com");
        // Grab the identity ETag, then revalidate -> 304 with no body.
        let (_ka, first) = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        let etag = header(&first, "ETag:").expect("etag present");
        let req = format!("GET /style.css HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\n\r\n");
        let (_k2, r304) = run(&v, &req, true, false);
        assert!(r304.starts_with("HTTP/1.1 304"), "{r304}");
        assert_eq!(r304.split("\r\n\r\n").nth(1), Some(""));
        // Connection: close still streams the body, with the header flipped.
        let (ka, rc) = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", false, false);
        assert!(!ka);
        assert!(rc.contains("Connection: close\r\n"), "{rc}");
        assert!(rc.ends_with(&"body { color: red; }\n".repeat(20)));
    }

    #[test]
    fn redirect_authority_omits_default_ports_only() {
        assert_eq!(redirect_authority("h", "443", "443"), "h"); // default https: omit
        assert_eq!(redirect_authority("h", "80", "80"), "h"); // default http: omit
        assert_eq!(redirect_authority("h", "", "443"), "h"); // empty: omit
        assert_eq!(redirect_authority("h", "8443", "443"), "h:8443"); // non-default: keep
    }

    #[test]
    fn peer_limiter_caps_per_ip_and_frees_on_drop() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let lim = PeerLimiter::new(2);
        let p1 = lim.try_acquire(ip);
        let p2 = lim.try_acquire(ip);
        assert!(p1.is_some() && p2.is_some());
        assert!(lim.try_acquire(ip).is_none(), "third from the same IP is refused");
        assert!(lim.try_acquire(other).is_some(), "a different IP is unaffected");
        drop(p1); // freeing one slot lets the same IP back in
        assert!(lim.try_acquire(ip).is_some(), "a freed slot is reusable");
        drop(p2);
    }

    #[test]
    fn peer_limiter_zero_means_unlimited() {
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        let lim = PeerLimiter::new(0);
        // Never refuses, never tracks (map stays empty even while permits live).
        let _a = lim.try_acquire(ip);
        let _b = lim.try_acquire(ip);
        assert!(lim.try_acquire(ip).is_some());
        assert!(lim.counts.lock().unwrap().is_empty());
    }

    /// Add a rootless (redirect-only) host to an existing table — what a
    /// `site www.example.com { cert; key; redirect * -> ... }` block builds.
    fn add_redirect_only(v: &mut Vhosts, host: &str, redirects: crate::config::Redirects) {
        v.sites.insert(
            host.to_string(),
            Arc::new(Site {
                root: None,
                cache: RwLock::new(Arc::new(cache::SiteCache::empty())),
                force_ssl: true,
                canonical_urls: false,
                redirects,
                policy: Arc::new(cache::Policy::new(Default::default())),
            }),
        );
    }

    #[test]
    fn redirect_only_vhost_301s_to_canonical_host() {
        let (_d, mut v) = fixture("example.com");
        add_redirect_only(&mut v, "www.example.com", rules("redirect * -> https://example.com$0"));
        let (_ka, r) = run(&v, "GET /page?x=1 HTTP/1.1\r\nHost: www.example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 301"));
        // Location is built from the config target, never the request Host.
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/page?x=1"));
    }

    #[test]
    fn a_redirect_only_vhost_answers_in_one_hop_on_the_plain_listener() {
        // The rule runs before the HTTP -> HTTPS upgrade, so http://www lands on
        // https://apex directly rather than via https://www.
        let (_d, mut v) = fixture("example.com");
        add_redirect_only(&mut v, "www.example.com", rules("redirect * -> https://example.com$0"));
        let (_ka, r) = run(&v, "GET /p HTTP/1.1\r\nHost: www.example.com\r\n\r\n", true, true);
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/p"));
    }

    #[test]
    fn a_redirect_only_vhost_404s_a_path_no_rule_matches() {
        let (_d, mut v) = fixture("example.com");
        add_redirect_only(&mut v, "www.example.com", rules("redirect /only -> /here"));
        let r = run(&v, "GET /other HTTP/1.1\r\nHost: www.example.com\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 404"), "{r}");
    }

    // ---- canonical_urls ----

    #[test]
    fn canonical_form_folds_the_html_spellings_onto_the_directory() {
        assert_eq!(canonical_form("/index.html").as_deref(), Some("/"));
        assert_eq!(canonical_form("/about.html").as_deref(), Some("/about/"));
        assert_eq!(canonical_form("/about/index.html").as_deref(), Some("/about/"));
        assert_eq!(canonical_form("/blog/a-post.html").as_deref(), Some("/blog/a-post/"));
        assert_eq!(canonical_form("/a/b/index.html").as_deref(), Some("/a/b/"));
        // "index" only counts as a whole segment.
        assert_eq!(canonical_form("/myindex.html").as_deref(), Some("/myindex/"));
        // Already canonical, or simply not an .html URL: serve it.
        assert!(canonical_form("/").is_none());
        assert!(canonical_form("/about/").is_none());
        assert!(canonical_form("/about").is_none());
        assert!(canonical_form("/style-0667c2b357.css").is_none());
        assert!(canonical_form("/index.htm").is_none());
    }

    #[test]
    fn canonical_form_output_never_needs_a_second_hop() {
        // The result never ends in .html, so the redirect cannot match again —
        // which is what makes this loop-free for any input.
        for p in ["/index.html", "/a.html", "/a/index.html", "/a/b/c.html", "/myindex.html"] {
            let once = canonical_form(p).expect("redirects");
            assert!(canonical_form(&once).is_none(), "{p} -> {once} would redirect again");
        }
    }

    #[test]
    fn canonical_urls_301s_the_html_forms() {
        let (_d, v) = fixture_canonical("example.com", Default::default());
        for (req, want) in [
            ("/index.html", "https://example.com/"),
            ("/about.html", "https://example.com/about/"),
            ("/about/index.html", "https://example.com/about/"),
            ("/blog/post.html", "https://example.com/blog/post/"),
        ] {
            let raw = format!("GET {req} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let r = run(&v, &raw, true, false).1;
            assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{req}: {r}");
            assert_eq!(header(&r, "Location:").as_deref(), Some(want), "{req}");
        }
    }

    #[test]
    fn canonical_urls_folds_percent_encoded_spellings_too() {
        // RFC 3986 §6.2.2.2: a percent-encoded unreserved character is the same
        // URI as its decoded form. Canonicalising the raw path let "/about%2Ehtml"
        // skip the fold entirely while still being served, and folded
        // "/ab%6Fut.html" onto a Location that was itself non-canonical — a
        // duplicate-content feature emitting duplicate URLs.
        let (_d, v) = fixture_canonical("example.com", Default::default());
        for req in ["/about.html", "/about%2Ehtml", "/ab%6Fut.html", "/ab%6Fut%2Ehtml"] {
            let raw = format!("GET {req} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let r = run(&v, &raw, true, false).1;
            assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{req}: {r}");
            assert_eq!(
                header(&r, "Location:").as_deref(),
                Some("https://example.com/about/"),
                "{req} must fold onto the one canonical spelling"
            );
        }
    }

    #[test]
    fn a_dir_index_redirect_lands_on_one_canonical_spelling() {
        let (_d, v) = fixture("example.com");
        for req in ["/about", "/ab%6Fut"] {
            let raw = format!("GET {req} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let r = run(&v, &raw, true, false).1;
            // `/about` is a page in the fixture, so it serves; the point here is
            // that both spellings agree on what they resolve to.
            assert!(!r.starts_with("HTTP/1.1 404"), "{req}: {r}");
        }
    }

    #[test]
    fn two_sites_sharing_a_root_get_separate_watcher_slots() {
        // The watcher used to key its rebuild bookkeeping by root path, so two
        // `site` blocks naming the same root shared one slot: whichever the
        // HashMap yielded first was rebuilt and the root marked done, leaving the
        // other serving boot-time content for the life of the process.
        let root = "/srv/www";
        assert_ne!(site_key("a.test", root), site_key("b.test", root));
        // Hostnames aliasing one block share an Arc and so resolve to one entry;
        // the key is stable for a given (host, root) pair across ticks.
        assert_eq!(site_key("a.test", root), site_key("a.test", root));
    }

    #[test]
    fn a_host_that_disagrees_with_sni_is_refused() {
        let (_d, v) = fixture("example.com");
        let raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Matching SNI: served normally.
        let mut s = MockStream::new(b"");
        handle_request(&mut s, raw.as_bytes(), &v, true, false, Some("example.com")).unwrap();
        let ok = String::from_utf8_lossy(&s.output).into_owned();
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");

        // A connection established for another name must not be usable to fetch
        // this host's content under that name's certificate and header policy.
        let mut s = MockStream::new(b"");
        handle_request(&mut s, raw.as_bytes(), &v, true, false, Some("other.example")).unwrap();
        let bad = String::from_utf8_lossy(&s.output).into_owned();
        assert!(bad.starts_with("HTTP/1.1 404"), "{bad}");

        // The plain listener has no SNI, so nothing to bind against.
        let mut s = MockStream::new(b"");
        handle_request(&mut s, raw.as_bytes(), &v, true, false, None).unwrap();
        let plain = String::from_utf8_lossy(&s.output).into_owned();
        assert!(plain.starts_with("HTTP/1.1 200 OK"), "{plain}");
    }

    #[test]
    fn canonical_urls_keeps_the_query_string() {
        let (_d, v) = fixture_canonical("example.com", Default::default());
        let r = run(&v, "GET /about.html?ref=x HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/about/?ref=x"));
    }

    #[test]
    fn an_explicit_rule_beats_canonicalisation() {
        // A page that MOVED must reach its new home in one hop, not be folded
        // onto its own old directory first.
        let (_d, v) = fixture_canonical(
            "example.com",
            rules("redirect /services/old-name.html -> /services/new-name/"),
        );
        let r = run(&v, "GET /services/old-name.html HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(
            header(&r, "Location:").as_deref(),
            Some("https://example.com/services/new-name/")
        );
    }

    #[test]
    fn canonical_urls_leaves_the_acme_challenge_alone() {
        // Not that a token ends in .html, but the exemption must not depend on
        // that: it is the same guard the rules use.
        let (d, v) = fixture_canonical("example.com", Default::default());
        d.write(".well-known/acme-challenge/tok", b"key-auth");
        let r = run(
            &v,
            "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: example.com\r\n\r\n",
            true,
            true,
        )
        .1;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }

    #[test]
    fn canonical_urls_is_off_by_default() {
        // The flag changes what a URL does, so a site that says nothing keeps
        // serving what it served.
        let (_d, v) = fixture("example.com");
        let r = run(&v, "GET /about.html HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(!r.starts_with("HTTP/1.1 301"), "{r}");
    }

    // ---- configured redirect rules on a content site ----

    #[test]
    fn a_rule_beats_the_content_at_the_same_path() {
        // /about.html exists in the fixture; the rule must win.
        let (_d, v) = fixture_redirects("example.com", rules("redirect /about.html -> /moved"));
        let r = run(&v, "GET /about.html HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 301"), "{r}");
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/moved"));
    }

    #[test]
    fn a_bare_path_target_gets_this_hosts_scheme_and_authority() {
        let (_d, v) = fixture_redirects("example.com", rules("redirect /old -> /new"));
        let r = run(&v, "GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/new"));
        // On the plain listener a site that serves HTTP stays on http://.
        let r = run(&v, "GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("http://example.com/new"));
    }

    #[test]
    fn an_absolute_target_is_emitted_verbatim() {
        let (_d, v) = fixture_redirects("example.com", rules("redirect /gone -> https://other.test/x"));
        let r = run(&v, "GET /gone HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://other.test/x"));
    }

    #[test]
    fn a_prefix_rule_carries_the_remainder_over() {
        let (_d, v) = fixture_redirects("example.com", rules("redirect /docs/* -> /help/$1"));
        let r = run(&v, "GET /docs/a/b HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/help/a/b"));
    }

    #[test]
    fn the_query_string_survives_a_redirect() {
        let (_d, v) = fixture_redirects("example.com", rules("redirect /old -> /new"));
        let r = run(&v, "GET /old?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/new?a=1&b=2"));
    }

    #[test]
    fn a_target_with_its_own_query_is_not_given_a_second_one() {
        // Two '?' would make the Location unparseable, so the rule's own query
        // wins and the request's is dropped.
        let (_d, v) = fixture_redirects("example.com", rules("redirect /old -> /new?kept=1"));
        let r = run(&v, "GET /old?a=1 HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(header(&r, "Location:").as_deref(), Some("https://example.com/new?kept=1"));
    }

    #[test]
    fn rules_match_the_raw_percent_encoded_path() {
        // The rule is written as the client sends it; a decoded form does not
        // match, which keeps matching free of double-decoding ambiguity.
        let (_d, v) = fixture_redirects("example.com", rules("redirect /a%20b -> /moved"));
        let hit = run(&v, "GET /a%20b HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(hit.starts_with("HTTP/1.1 301"), "{hit}");
        let miss = run(&v, "GET /a+b HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(!miss.starts_with("HTTP/1.1 301"), "{miss}");
    }

    #[test]
    fn a_path_no_rule_matches_is_served_normally() {
        let (_d, v) = fixture_redirects("example.com", rules("redirect /old -> /new"));
        let r = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }

    #[test]
    fn the_acme_prefix_is_exempt_from_a_catch_all_rule() {
        // Otherwise adding `redirect * -> ...` to a site would silently break its
        // certificate renewal.
        let (d, v) = fixture_redirects("example.com", rules("redirect * -> https://other.test$0"));
        d.write(".well-known/acme-challenge/tok", b"key-auth");
        let r = run(
            &v,
            "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: example.com\r\n\r\n",
            true,
            true,
        )
        .1;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.ends_with("key-auth"), "{r}");
    }

    #[test]
    fn every_redirect_this_server_emits_is_a_301() {
        // One emitter, one status — the rule path, the HTTP -> HTTPS upgrade and
        // the trailing-slash canonicalisation must not drift apart.
        let (_d, v) = fixture_redirects("example.com", rules("redirect /old -> /new"));
        for (raw, plain) in [
            ("GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n", false), // rule
            ("GET /blog HTTP/1.1\r\nHost: example.com\r\n\r\n", false), // dir index
        ] {
            let r = run(&v, raw, true, plain).1;
            assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{r}");
        }
        // ...and the force_ssl upgrade, which needs the flag on.
        let (_d2, v2) = fixture_with("example.com", true);
        let r = run(&v2, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true).1;
        assert!(r.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{r}");
    }

    #[test]
    fn percent_encoded_path_resolves() {
        let (_d, v) = fixture("example.com");
        let (_ka, r) = run(&v, "GET /%69ndex.html HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }

    #[test]
    fn connection_header_controls_keep_alive() {
        let (_d, v) = fixture("example.com");
        let close = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", true, false);
        assert!(!close.0);
        assert_eq!(header(&close.1, "Connection:").as_deref(), Some("close"));
        let ka = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(ka.0);
        let http10 = run(&v, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n", true, false);
        assert!(!http10.0, "HTTP/1.0 defaults to close");
        let forced = run(&v, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", false, false);
        assert!(!forced.0, "want_ka=false forces close (keep-alive cap reached)");
    }

    // ---- ACME live read ----

    #[test]
    fn acme_token_is_served_from_disk() {
        let (dir, v) = fixture("example.com");
        dir.write(".well-known/acme-challenge/tok-123", b"KEYAUTH");
        let (_ka, r) = run(&v, "GET /.well-known/acme-challenge/tok-123 HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert_eq!(header(&r, "Cache-Control:").as_deref(), Some("no-store"));
        assert!(r.ends_with("KEYAUTH"));

        let (_ka2, missing) = run(&v, "GET /.well-known/acme-challenge/absent HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(missing.starts_with("HTTP/1.1 404"));
    }

    #[cfg(unix)]
    #[test]
    fn acme_refuses_symlinked_challenge_dir() {
        use std::os::unix::fs::symlink;
        let (dir, v) = fixture("example.com");
        // Point acme-challenge at an out-of-root dir that holds a matching file.
        let outside = TempDir::new();
        std::fs::write(outside.path().join("secret"), b"private").unwrap();
        std::fs::create_dir_all(dir.path().join(".well-known")).unwrap();
        symlink(outside.path(), dir.path().join(".well-known").join("acme-challenge")).unwrap();
        let (_ka, r) = run(&v, "GET /.well-known/acme-challenge/secret HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false);
        assert!(r.starts_with("HTTP/1.1 404"), "symlinked parent must not be followed: {r}");
    }

    /// A FIFO in the challenge directory must not wedge the worker. Without
    /// O_NONBLOCK the read-only open(2) parks until a writer appears — forever,
    /// in practice — and since that happens before the is_file() check, the
    /// thread holds its connection slot for the life of the process. Enough of
    /// them take the plain listener down and ACME renewal with it.
    ///
    /// Run on a worker thread so a regression is a failed assert rather than a
    /// test binary that hangs until CI times out.
    #[cfg(unix)]
    #[test]
    fn acme_fifo_token_does_not_block_the_worker() {
        use std::ffi::CString;
        use std::sync::mpsc;

        let (dir, v) = fixture("example.com");
        let chal = dir.path().join(".well-known/acme-challenge");
        std::fs::create_dir_all(&chal).unwrap();
        let fifo = chal.join("tok");
        let c = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o644) },
            0,
            "mkfifo: {}",
            io::Error::last_os_error()
        );

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _keep = dir; // the fixture must outlive the request
            let (_ka, r) = run(
                &v,
                "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: example.com\r\n\r\n",
                true,
                false,
            );
            let _ = tx.send(r);
        });

        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("request must complete; a FIFO token must not park the worker in open()");
        assert!(r.starts_with("HTTP/1.1 404"), "a FIFO is not a regular file: {r}");
    }

    // ---- serve_over: the keep-alive loop over a byte stream ----

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn serve_over_handles_pipelined_requests() {
        let (_d, v) = fixture("example.com");
        let two = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nGET /about HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut s = MockStream::new(two.as_bytes());
        serve_over(&mut s, &v, Vec::new(), false, deadline(), &Phase::default(), None);
        let out = String::from_utf8_lossy(&s.output);
        assert_eq!(out.matches("HTTP/1.1 200 OK").count(), 2, "both pipelined requests answered");
    }

    #[test]
    fn serve_over_rejects_oversized_head_with_431() {
        let (_d, v) = fixture("example.com");
        let mut s = MockStream::new(&vec![b'A'; 9000]); // no CRLFCRLF, over MAX_HEADER_BYTES
        serve_over(&mut s, &v, Vec::new(), false, deadline(), &Phase::default(), None);
        assert!(String::from_utf8_lossy(&s.output).contains("431"));
    }

    #[test]
    fn serve_over_clean_close_on_empty_input() {
        let (_d, v) = fixture("example.com");
        let mut s = MockStream::new(b"");
        serve_over(&mut s, &v, Vec::new(), false, deadline(), &Phase::default(), None);
        assert!(s.output.is_empty(), "a client that sends nothing gets nothing");
    }

    // ---- TLS load path (against the repo's test certs) ----

    /// Shorthand for passing a fixture path where the config wants a `&str`.
    fn s(p: &std::path::Path) -> &str {
        p.to_str().unwrap()
    }

    fn cfg_site(host: &str, root: &str, cert: &str, key: &str) -> Config {
        cfg_of(vec![vh_site_full(host, Some(root), cert, key)])
    }

    fn cfg_of(sites: Vec<crate::config::SiteConfig>) -> Config {
        Config {
            host: "127.0.0.1".into(),
            port: "0".into(),
            http_host: String::new(),
            http_port: String::new(),
            headers: Default::default(),
            max_conns_per_ip: 64,
            max_response_secs: 0,
            storage: crate::config::Storage::Memory,
            disk_cache: None,
            sites,
        }
    }

    fn vh_site_full(
        host: &str,
        root: Option<&str>,
        cert: &str,
        key: &str,
    ) -> crate::config::SiteConfig {
        crate::config::SiteConfig {
            hosts: vec![host.into()],
            root: root.map(Into::into),
            cert: cert.into(),
            key: key.into(),
            force_ssl: false,
            canonical_urls: false,
            redirects: Default::default(),
            tuning: Default::default(),
            headers: Default::default(),
        }
    }

    #[test]
    fn build_tls_accepts_a_matching_pair_covering_the_host() {
        let tc = crate::testutil::test_certs();
        let cfg = cfg_site("localhost", "www", s(&tc.cert), s(&tc.key));
        assert!(build_tls(&cfg).is_ok());
    }

    #[test]
    fn build_tls_rejects_a_mismatched_key() {
        // An RSA cert against an unrelated EC key: not a pair.
        let tc = crate::testutil::test_certs();
        let cfg = cfg_site("localhost", "www", s(&tc.cert), s(&tc.other_key));
        let e = build_tls(&cfg).err().unwrap();
        assert!(e.contains("does not match"), "{e}");
    }

    #[test]
    fn build_tls_rejects_a_host_the_cert_does_not_cover() {
        // The fixture cert only covers "localhost".
        let tc = crate::testutil::test_certs();
        let cfg = cfg_site("example.com", "www", s(&tc.cert), s(&tc.key));
        assert!(build_tls(&cfg).is_err());
    }

    #[test]
    fn build_tls_rejects_a_missing_cert_file() {
        let tc = crate::testutil::test_certs();
        let cfg = cfg_site("localhost", "www", "target/test-certs/does-not-exist.pem", s(&tc.key));
        assert!(build_tls(&cfg).is_err());
    }

    #[test]
    fn build_runtime_builds_vhosts_and_tls_together() {
        let tc = crate::testutil::test_certs();
        let cfg = cfg_site("localhost", "www", s(&tc.cert), s(&tc.key));
        let rt = build_runtime(&cfg).expect("runtime built");
        assert!(rt.vhosts.sites.contains_key("localhost"));
        let cache = rt.vhosts.sites["localhost"].cache.read().unwrap();
        assert!(cache.map.contains_key("/index.html"), "www/index.html should be cached");
    }

    // ---- DeadlineIo: the deadlines enforced below rustls ----

    fn socket_pair() -> (TcpStream, TcpStream) {
        use std::net::TcpListener as L;
        let listener = L::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    #[test]
    fn deadline_io_refuses_a_response_below_the_minimum_rate() {
        let (mut server, _client) = socket_pair();
        // A window that has already elapsed with nothing delivered: the very next
        // write is refused as TimedOut, not WouldBlock, so it propagates out of
        // rustls instead of being retried forever.
        let mut dl = DeadlineIo {
            inner: &mut server,
            idle: Duration::from_secs(0),
            window: Instant::now(),
            moved: 0,
            deadline: None,
            phase: Phase::default(),
        };
        let err = dl.write(b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn deadline_io_allows_a_window_that_met_the_minimum() {
        let (mut server, _client) = socket_pair();
        // Same elapsed window, but the minimum was already delivered in it: a
        // genuinely slow-but-real download must not be truncated.
        let mut dl = DeadlineIo {
            inner: &mut server,
            idle: Duration::from_secs(0),
            window: Instant::now(),
            moved: MIN_PROGRESS_BYTES,
            deadline: None,
            phase: Phase::default(),
        };
        assert_eq!(dl.write(b"hello").unwrap(), 5);
        // The window rolled over on the way in, so the next one is judged on
        // its own merits rather than on the burst that satisfied this one.
        assert_eq!(dl.moved, 5);
    }

    #[test]
    fn deadline_io_enforces_the_armed_phase_deadline() {
        let (mut server, _client) = socket_pair();
        let phase = Phase::default();
        let dl = DeadlineIo {
            inner: &mut server,
            idle: Duration::from_secs(30),
            window: Instant::now(),
            moved: 0,
            deadline: None,
            phase: phase.clone(),
        };
        // Disarmed: a read is governed by the socket timeout alone.
        assert!(dl.check().is_ok());
        // Armed in the past: this is what bounds a client stalled inside a
        // partial TLS record, where serve_over never regains control.
        phase.arm(Instant::now() - Duration::from_secs(1));
        let err = dl.check().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        // Disarming again releases it — the response phase uses the rate check.
        phase.disarm();
        assert!(dl.check().is_ok());
    }

    #[test]
    fn deadline_io_read_starts_a_fresh_window() {
        let (mut server, mut client) = socket_pair();
        client.write_all(b"ping").unwrap();
        let mut dl = DeadlineIo {
            inner: &mut server,
            idle: Duration::from_secs(30),
            window: Instant::now() - Duration::from_secs(120),
            moved: 0,
            deadline: None,
            phase: Phase::default(),
        };
        let mut b = [0u8; 4];
        assert_eq!(dl.read(&mut b).unwrap(), 4);
        // An idle keep-alive gap must not condemn the next response: reading the
        // request head restarts the window rather than carrying the stale one in.
        assert!(dl.window.elapsed() < Duration::from_secs(1));
        assert!(dl.check_rate().is_ok());
    }

    // ---- handle_request edge cases ----

    #[test]
    fn overlong_path_is_400() {
        let (_d, v) = fixture("example.com");
        let long = format!("/{}", "a".repeat(1100)); // >= MAX_PATH_LEN (1024)
        let raw = format!("GET {long} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(run(&v, &raw, true, false).1.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn malformed_request_line_is_400() {
        let (_d, v) = fixture("example.com");
        // Two tokens only: no HTTP version.
        assert!(run(&v, "GET /\r\nHost: example.com\r\n\r\n", true, false).1.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn head_on_an_error_has_no_body() {
        let (_d, v) = fixture("example.com");
        let r = run(&v, "HEAD /missing HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 404"));
        assert_eq!(r.split("\r\n\r\n").nth(1), Some(""), "HEAD error must carry no body");
    }

    #[test]
    fn host_header_with_port_still_matches_the_site() {
        let (_d, v) = fixture("example.com");
        let r = run(&v, "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    }

    #[test]
    fn conditional_get_preserves_the_negotiated_encoding() {
        let (_d, v) = fixture("example.com");
        let first = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br\r\n\r\n", true, false).1;
        assert_eq!(header(&first, "Content-Encoding:").as_deref(), Some("br"));
        let etag = header(&first, "ETag:").unwrap(); // the brotli variant's ETag
        let raw = format!("GET /style.css HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: br\r\nIf-None-Match: {etag}\r\n\r\n");
        let r = run(&v, &raw, true, false).1;
        assert!(r.starts_with("HTTP/1.1 304"), "{r}");
        // The 304 must echo the encoding and Vary so a cache keeps the br body usable.
        assert_eq!(header(&r, "Content-Encoding:").as_deref(), Some("br"));
        assert_eq!(header(&r, "Vary:").as_deref(), Some("Accept-Encoding"));
    }

    // ---- serve_acme_token limits ----

    #[test]
    fn acme_rejects_malformed_oversized_and_missing_tokens() {
        let (dir, v) = fixture("example.com");
        // A '.' is outside the token alphabet.
        assert!(run(&v, "GET /.well-known/acme-challenge/a.b HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1.starts_with("HTTP/1.1 404"));
        // Over the 128-char token-name limit.
        let long = "a".repeat(130);
        let raw = format!("GET /.well-known/acme-challenge/{long} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert!(run(&v, &raw, true, false).1.starts_with("HTTP/1.1 404"));
        // A well-formed token whose file exceeds the byte cap is refused.
        dir.write(".well-known/acme-challenge/big", &vec![b'x'; 5000]); // > ACME_TOKEN_MAX_BYTES (4096)
        assert!(run(&v, "GET /.well-known/acme-challenge/big HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1.starts_with("HTTP/1.1 404"));
    }

    // ---- build_vhosts validation ----

    fn vh_cfg(sites: Vec<crate::config::SiteConfig>) -> Config {
        cfg_of(sites)
    }
    fn vh_site(host: &str, root: &str) -> crate::config::SiteConfig {
        vh_site_full(host, Some(root), "c", "k")
    }

    #[test]
    fn build_vhosts_happy_path_indexes_every_site() {
        let a = TempDir::new();
        a.write("index.html", b"a");
        let b = TempDir::new();
        b.write("index.html", b"b");
        // A rootless redirect-only host is an ordinary site in the same table.
        let mut w = vh_site_full("www.a.com", None, "c", "k");
        w.redirects = rules("redirect * -> https://a.com$0");
        let cfg = vh_cfg(vec![
            vh_site("a.com", a.path().to_str().unwrap()),
            vh_site("b.com", b.path().to_str().unwrap()),
            w,
        ]);
        let vh = build_vhosts(&cfg).expect("built");
        assert!(vh.sites.contains_key("a.com") && vh.sites.contains_key("b.com"));
        let redirect_only = &vh.sites["www.a.com"];
        assert!(redirect_only.root.is_none());
        assert!(redirect_only.cache.read().unwrap().map.is_empty());
        assert_eq!(
            redirect_only.redirects.resolve("/p").as_deref(),
            Some("https://a.com/p")
        );
    }

    #[test]
    fn build_vhosts_rejects_duplicate_host_across_sites() {
        let a = TempDir::new();
        a.write("index.html", b"a");
        let b = TempDir::new();
        b.write("index.html", b"b");
        let cfg = vh_cfg(vec![
            vh_site("dup.com", a.path().to_str().unwrap()),
            vh_site("dup.com", b.path().to_str().unwrap()),
        ]);
        assert!(build_vhosts(&cfg).err().unwrap().contains("duplicate host"));
    }

    #[test]
    fn build_vhosts_rejects_a_content_site_colliding_with_a_redirect_only_one() {
        // Both are sites now, so the one duplicate-host check covers what used to
        // need a separate "is both a site and a redirect source" rule.
        let a = TempDir::new();
        a.write("index.html", b"a");
        let mut w = vh_site_full("a.com", None, "c", "k");
        w.redirects = rules("redirect * -> https://b.com$0");
        let cfg = vh_cfg(vec![vh_site("a.com", a.path().to_str().unwrap()), w]);
        assert!(build_vhosts(&cfg).err().unwrap().contains("duplicate host"));
    }

    #[test]
    fn build_vhosts_rejects_a_non_directory_root() {
        let d = TempDir::new();
        d.write("a-file", b"x");
        let cfg = vh_cfg(vec![vh_site("a.com", d.path().join("a-file").to_str().unwrap())]);
        assert!(build_vhosts(&cfg).err().unwrap().contains("is not a directory"));
    }

    #[test]
    fn build_vhosts_rejects_a_missing_root() {
        let cfg = vh_cfg(vec![vh_site("a.com", "/no/such/root/anywhere")]);
        assert!(build_vhosts(&cfg).is_err());
    }

    // ---- build_tls extra paths ----

    #[test]
    fn build_tls_rejects_an_empty_cert_file() {
        let d = TempDir::new();
        d.write("empty.pem", b"");
        let cfg = cfg_site("localhost", "www", d.path().join("empty.pem").to_str().unwrap(), "tls/key.pem");
        assert!(build_tls(&cfg).is_err());
    }

    #[test]
    fn build_tls_builds_a_redirect_only_host() {
        // A rootless site serves no content but still terminates TLS, so it must
        // get a certificate from the same single pass as every other site.
        let tc = crate::testutil::test_certs();
        let mut w = vh_site_full("localhost", None, s(&tc.cert), s(&tc.key));
        w.redirects = rules("redirect * -> https://apex.example$0");
        assert!(build_tls(&cfg_of(vec![w])).is_ok());
    }

    // ---- config -> runtime wiring ----

    #[test]
    fn build_runtime_applies_server_tuning_to_the_built_cache() {
        // The whole point of the feature: settings in the Config must reach the
        // cache that build_runtime produces. www/index.html is compressible, so
        // with the defaults it WOULD carry gzip/br variants.
        let tc = crate::testutil::test_certs();
        let mut cfg = cfg_site("localhost", "www", s(&tc.cert), s(&tc.key));
        cfg.sites[0].tuning.compression = false;
        cfg.sites[0].tuning.cache_max_age = 77;
        let rt = build_runtime(&cfg).expect("runtime built");
        let site = &rt.vhosts.sites["localhost"];
        let cache = site.cache.read().unwrap();
        let e = match cache.map.get("/index.html").expect("index cached") {
            cache::Cached::Mem(m) => m,
            cache::Cached::Disk(_) => panic!("memory storage expected"),
        };
        assert!(e.gzip.is_none() && e.br.is_none(), "compression=off must reach the cache");
        assert!(!e.vary);
        assert_eq!(&*e.cache_control, "public, max-age=77, must-revalidate");
        // And the site carries the policy the watcher will rebuild it with.
        assert!(!site.policy.t.compression);
        assert_eq!(site.policy.t.cache_max_age, 77);
    }

    #[test]
    fn the_precomputed_errors_are_charged_to_the_ram_budget() {
        // max_total_bytes counts every byte actually retained, and these buffers
        // are retained for the life of the process. Leaving them uncounted would
        // let the budget report success while overshooting.
        let one_set = ErrorPages::new(&crate::config::HeaderConfig::default().render())
            .retained_bytes();
        let d = TempDir::new();
        d.write("index.html", b"x");
        let build = |budget: usize| {
            let mut s = vh_site("a.com", d.path().to_str().unwrap());
            s.tuning.max_total_bytes = budget;
            build_vhosts(&cfg_of(vec![s]))
        };
        // A boot holds two sets: the server-level one and this site's. A budget
        // that fits only one must fail, even though the content is a single byte.
        let e = build(one_set).err().expect("one set of errors does not fit two");
        assert!(build(2 * one_set + 4096).is_ok(), "both sets plus the content fit");
        // The message must name the error responses. Pointing at the document
        // root would send the operator after content that was never read.
        assert!(e.contains("max_total_bytes"), "{e}");
        assert!(e.contains("precomputed error responses"), "{e}");
        assert!(!e.contains(d.path().to_str().unwrap()), "the root is not the cause: {e}");
    }

    #[test]
    fn the_error_page_budget_holds_where_the_content_walk_does_not_run() {
        // The two configurations the content walk never checks: Disk storage
        // keeps no bodies in RAM, so `walk` skips the budget entirely, and a
        // redirect-only site has no root to walk. The error buffers are resident
        // in both, so the ceiling has to be enforced outside the walk.
        let one_set = ErrorPages::new(&crate::config::HeaderConfig::default().render())
            .retained_bytes();
        let d = TempDir::new();
        d.write("index.html", b"x");
        let cachedir = TempDir::new();
        let disk = |budget: usize| {
            let mut s = vh_site("a.com", d.path().to_str().unwrap());
            s.tuning.max_total_bytes = budget;
            let mut cfg = cfg_of(vec![s]);
            cfg.storage = crate::config::Storage::Disk;
            cfg.disk_cache = Some(cachedir.path().to_str().unwrap().into());
            build_vhosts(&cfg)
        };
        assert!(disk(one_set).is_err(), "disk storage still holds two sets in RAM");
        assert!(disk(2 * one_set).is_ok(), "two sets fit; the bodies are on disk");
        // Redirect-only: 30 hosts, each with its own set, and no root anywhere.
        let redirect_only = |count: usize, budget: usize| {
            let sites: Vec<_> = (0..count)
                .map(|i| {
                    let mut s = vh_site_full(&format!("h{i}.com"), None, "c", "k");
                    s.tuning.max_total_bytes = budget;
                    s
                })
                .collect();
            build_vhosts(&cfg_of(sites))
        };
        assert!(redirect_only(30, 30 * one_set).is_err(), "31 sets do not fit 30");
        assert!(redirect_only(30, 31 * one_set).is_ok(), "31 sets fit 31");
    }

    #[test]
    fn build_vhosts_gives_each_site_its_own_settings() {
        // The point of per-site overrides: two sites in one process, different
        // Cache-Control and different response headers.
        let da = TempDir::new();
        da.write("index.html", "body { color: red; }\n".repeat(20).as_bytes());
        let db = TempDir::new();
        db.write("index.html", b"b");
        let mut a = vh_site("a.com", da.path().to_str().unwrap());
        a.tuning.cache_max_age = 11;
        a.headers.csp = "default-src 'self'".into();
        let mut b = vh_site("b.com", db.path().to_str().unwrap());
        b.tuning.cache_max_age = 22;
        b.tuning.compression = false;
        let vh = build_vhosts(&cfg_of(vec![a, b])).expect("built");
        let (sa, sb) = (&vh.sites["a.com"], &vh.sites["b.com"]);
        assert_eq!(sa.policy.t.cache_max_age, 11);
        assert_eq!(sb.policy.t.cache_max_age, 22);
        assert!(sa.policy.t.compression && !sb.policy.t.compression);
        assert!(sa.policy.security_headers.contains("Content-Security-Policy: default-src 'self'"));
        assert!(!sb.policy.security_headers.contains("Content-Security-Policy"));
        // The override reaches each site's precomputed errors, not only its 200s.
        let a404 = String::from_utf8_lossy(sa.policy.errors.not_found.bytes(true, false));
        let b404 = String::from_utf8_lossy(sb.policy.errors.not_found.bytes(true, false));
        assert!(a404.contains("Content-Security-Policy: default-src 'self'"), "{a404}");
        assert!(!b404.contains("Content-Security-Policy"), "{b404}");
        // ...and the override actually reached the bytes each cache holds.
        let ca = sa.cache.read().unwrap();
        match ca.map.get("/index.html").unwrap() {
            cache::Cached::Mem(m) => {
                assert_eq!(&*m.cache_control, "public, max-age=11, must-revalidate");
                assert!(m.br.is_some(), "a.com keeps compression on");
            }
            cache::Cached::Disk(_) => panic!("memory storage expected"),
        }
    }

    #[test]
    fn a_sites_own_headers_cover_its_errors_and_redirects() {
        // A per-site csp must not stop at the 200s the cache baked it into.
        let (_d, mut v) = fixture("example.com");
        let h = crate::config::HeaderConfig { csp: "default-src 'none'".into(), ..Default::default() };
        let site = v.sites.get_mut("example.com").unwrap();
        *site = Arc::new(Site {
            root: site.root.clone(),
            cache: RwLock::new(Arc::new(cache::SiteCache::empty())),
            force_ssl: false,
            canonical_urls: false,
            redirects: rules("redirect /old -> /new"),
            policy: Arc::new(cache::Policy::with_headers(
                Default::default(),
                &h,
                crate::config::Storage::Memory,
                Default::default(),
            )),
        });
        for raw in [
            "GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n",     // 301
            "GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n", // 404
        ] {
            let r = run(&v, raw, true, false).1;
            assert_eq!(header(&r, "Content-Security-Policy:").as_deref(), Some("default-src 'none'"), "{r}");
        }
        // A response sent before any site is known keeps the server-level block.
        let r = run(&v, "GET / HTTP/1.1\r\nHost: nope.test\r\n\r\n", true, false).1;
        assert!(r.starts_with("HTTP/1.1 404"));
        assert!(header(&r, "Content-Security-Policy:").is_none(), "{r}");
    }

    #[test]
    fn build_vhosts_propagates_force_ssl_to_every_alias() {
        let a = TempDir::new();
        a.write("index.html", b"a");
        let b = TempDir::new();
        b.write("index.html", b"b");
        let mut s1 = vh_site("a.com", a.path().to_str().unwrap());
        s1.hosts = vec!["a.com".into(), "www.a.com".into()]; // aliases share one Site
        s1.force_ssl = true;
        let s2 = vh_site("b.com", b.path().to_str().unwrap()); // force_ssl off
        let cfg = vh_cfg(vec![s1, s2]);
        let vh = build_vhosts(&cfg).unwrap();
        assert!(vh.sites["a.com"].force_ssl);
        assert!(vh.sites["www.a.com"].force_ssl, "an alias must inherit force_ssl");
        assert!(!vh.sites["b.com"].force_ssl, "force_ssl is per site, not global");
    }

    #[test]
    fn conditional_get_echoes_the_configured_cache_control() {
        // The 304 path re-emits entry.cache_control (an Arc<str> since tuning
        // made it runtime-generated) — it must carry the configured max-age.
        let t = crate::config::Tuning { cache_max_age: 4242, ..Default::default() };
        let (_d, v) = fixture_tuned("example.com", false, t);
        let first = run(&v, "GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n", true, false).1;
        assert_eq!(
            header(&first, "Cache-Control:").as_deref(),
            Some("public, max-age=4242, must-revalidate")
        );
        let etag = header(&first, "ETag:").unwrap();
        let raw = format!("GET /style.css HTTP/1.1\r\nHost: example.com\r\nIf-None-Match: {etag}\r\n\r\n");
        let r = run(&v, &raw, true, false).1;
        assert!(r.starts_with("HTTP/1.1 304"), "{r}");
        assert_eq!(
            header(&r, "Cache-Control:").as_deref(),
            Some("public, max-age=4242, must-revalidate"),
            "a 304 must repeat the configured Cache-Control"
        );
    }

    #[test]
    fn force_ssl_site_still_redirects_head_without_a_body() {
        let (_d, v) = fixture_with("example.com", true);
        let (_ka, r) = run(&v, "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n", true, true);
        assert!(r.starts_with("HTTP/1.1 301"), "{r}");
        assert_eq!(r.split("\r\n\r\n").nth(1), Some(""));
    }
}
