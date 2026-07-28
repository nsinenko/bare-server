#!/bin/sh
# Benchmark bare-server end to end: build it, generate a reproducible corpus,
# start it, measure, tear it down.
#
#   ./bench/bench.sh                # everything
#   ./bench/bench.sh --quick        # shorter load phases
#   ./bench/bench.sh --no-load      # only the deterministic measurements
#
# Requires: cargo, openssl, curl. A load generator (wrk or oha) is used if one
# is present; without it the deterministic measurements still run.
#
# What is deterministic and what is not:
#   - Compression ratios, binary size and cache footprint depend only on the
#     corpus and the build. They reproduce anywhere.
#   - Throughput and latency depend on the machine, the kernel and the load
#     generator sharing the same CPUs. Treat them as a shape, not a score, and
#     never compare numbers taken on different hosts.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=${BENCH_WORK:-$ROOT/target/bench}
CORPUS=$WORK/www
PORT_HTTPS=${BENCH_PORT_HTTPS:-18443}
PORT_HTTP=${BENCH_PORT_HTTP:-18080}
DURATION=10
CONNS=64
THREADS=4
RUN_LOAD=1

for arg in "$@"; do
    case $arg in
        --quick)   DURATION=3 ;;
        --no-load) RUN_LOAD=0 ;;
        -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
# Portable sub-second clock: macOS `date` has no %N.
now()  { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
# Portable byte count, no stat(1) flag differences.
bytes() { wc -c < "$1" | tr -d ' '; }

SRV_PID=""
cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
    [ -n "$SRV_PID" ] && wait "$SRV_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------- corpus
#
# Synthesised rather than checked in, so the repository carries no megabytes of
# filler. Deterministic: same bytes on every machine, so compression ratios are
# comparable across runs and hosts.
build_corpus() {
    [ -d "$CORPUS" ] && rm -rf "$CORPUS"
    mkdir -p "$CORPUS"
    perl -e '
        my $dir = shift;
        # A tiny LCG, seeded fixed, so every run produces identical bytes.
        my $seed = 20260728;
        sub rnd { $seed = ($seed * 1103515245 + 12345) % 2147483648; return $seed; }
        my @words = qw(server static cache response header request compress brotli
                       gzip socket handshake certificate listener virtual host redirect
                       canonical immutable revalidate throughput latency buffer);
        sub prose {
            my $n = shift; my $s = "";
            $s .= $words[rnd() % scalar(@words)] . " " while length($s) < $n;
            return $s;
        }
        sub page {
            my ($title, $n) = @_;
            my $body = "";
            $body .= "<p>" . prose(400) . "</p>\n" while length($body) < $n;
            return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
                 . "<title>$title</title>\n<link rel=\"stylesheet\" href=\"/app.css\">\n"
                 . "</head>\n<body>\n<h1>$title</h1>\n$body</body></html>\n";
        }
        sub put { my ($p, $c) = @_; open my $fh, ">", "$dir/$p" or die $!; print $fh $c; close $fh; }

        put("index.html", page("Index", 9000));
        mkdir "$dir/articles";
        for my $i (1 .. 20) { put("articles/post-$i.html", page("Post $i", 6000 + rnd() % 24000)); }
        # A stylesheet and a script, the two assets that dominate a real page load.
        my $css = ""; $css .= ".c" . rnd() . "{margin:" . (rnd() % 40) . "px;padding:2px;color:#3a3a3a}\n" while length($css) < 40000;
        put("app.css", $css);
        my $js = ""; $js .= "function f" . rnd() . "(a,b){return a*" . (rnd() % 99) . "+b;}\n" while length($js) < 180000;
        put("app.js", $js);
        # A fingerprinted asset: 8+ hex digits, so it gets the immutable policy.
        put("style-0667c2b357.css", $css);
        # An already-compressed type: must be skipped by the compressor.
        my $png = "\x89PNG\r\n\x1a\n"; $png .= chr(rnd() % 256) while length($png) < 200000;
        put("photo.png", $png);
        # A file under min_compress_bytes: stored identity-only.
        put("tiny.txt", "ok\n");
    ' "$CORPUS"
}

# ---------------------------------------------------------------------- build
say "Build"
BUILD_START=$(now)
( cd "$ROOT" && cargo build --release --locked ) >/dev/null 2>&1
BUILD_END=$(now)
BIN=$ROOT/target/release/bare-server
note "cargo build --release --locked: $(perl -e "printf '%.1f', $BUILD_END - $BUILD_START")s"
note "binary: $(bytes "$BIN") bytes ($(perl -e "printf '%.2f', $(bytes "$BIN")/1048576") MiB, host target)"
note "$(uname -sm), $( (sysctl -n machdep.cpu.brand_string 2>/dev/null) || (grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2-) || echo 'unknown cpu')"

say "Corpus"
build_corpus
CORPUS_BYTES=$(find "$CORPUS" -type f -exec cat {} + | wc -c | tr -d ' ')
CORPUS_FILES=$(find "$CORPUS" -type f | wc -l | tr -d ' ')
note "$CORPUS_FILES files, $CORPUS_BYTES bytes on disk"

# ------------------------------------------------------------------------ tls
mkdir -p "$WORK/tls"
if [ ! -f "$WORK/tls/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$WORK/tls/key.pem" -out "$WORK/tls/cert.pem" \
        -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
        >/dev/null 2>&1
fi

cat > "$WORK/bench.conf" <<EOF
listen = 127.0.0.1:$PORT_HTTPS
listen_http = 127.0.0.1:$PORT_HTTP

site localhost {
    root = $CORPUS
    cert = $WORK/tls/cert.pem
    key  = $WORK/tls/key.pem
}
EOF

# ------------------------------------------------------------------- start up
say "Startup"
BOOT_START=$(now)
"$BIN" "$WORK/bench.conf" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
# Ready = the port answers. Compression runs before the listener binds, so this
# is exactly the boot cost that matters: how long until the first byte can be
# served after a restart.
#
# Note the URL host is `localhost`, not `127.0.0.1`: the server selects a site
# by SNI, and a client connecting to an IP literal sends no SNI at all, so the
# handshake is refused with an access_denied alert. Every client below must use
# the hostname, and --ipv4 keeps them on the address the server bound.
i=0
until curl -sk --ipv4 -o /dev/null "https://localhost:$PORT_HTTPS/" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 600 ] && { echo "server failed to start:"; cat "$WORK/server.log"; exit 1; }
    perl -e 'select(undef,undef,undef,0.05)'
done
BOOT_END=$(now)
note "boot to first served byte: $(perl -e "printf '%.2f', $BOOT_END - $BOOT_START")s (includes brotli q11 over the whole corpus)"
grep -i 'cached' "$WORK/server.log" | sed 's/^/   /' || true
RSS=$(ps -o rss= -p "$SRV_PID" | tr -d ' ')
note "resident memory: $(perl -e "printf '%.1f', $RSS/1024") MiB (storage = memory)"

# ------------------------------------------------------------------ integrity
say "Compression (deterministic — reproduces on any host)"
printf '   %-26s %10s %10s %10s %8s %8s\n' FILE IDENTITY GZIP BROTLI GZIP% BR%
for f in index.html app.css app.js articles/post-1.html photo.png tiny.txt; do
    id=$(curl -sk --ipv4 -o /dev/null -w '%{size_download}' "https://localhost:$PORT_HTTPS/$f")
    gz=$(curl -sk --ipv4 -H 'Accept-Encoding: gzip' -o /dev/null -w '%{size_download}' "https://localhost:$PORT_HTTPS/$f")
    br=$(curl -sk --ipv4 -H 'Accept-Encoding: br'   -o /dev/null -w '%{size_download}' "https://localhost:$PORT_HTTPS/$f")
    printf '   %-26s %10s %10s %10s %7s%% %7s%%\n' "$f" "$id" "$gz" "$br" \
        "$(perl -e "printf '%.0f', 100-100*$gz/$id")" "$(perl -e "printf '%.0f', 100-100*$br/$id")"
done
note "photo.png and tiny.txt are expected to show 0% — already-compressed type, and under min_compress_bytes."

# ----------------------------------------------------------------------- load
if [ "$RUN_LOAD" -eq 0 ]; then
    say "Load phases skipped (--no-load)"
    exit 0
fi

LOADER=""
command -v wrk >/dev/null 2>&1 && LOADER=wrk
[ -z "$LOADER" ] && command -v oha >/dev/null 2>&1 && LOADER=oha
if [ -z "$LOADER" ]; then
    say "No load generator found (install wrk or oha) — skipping throughput"
    exit 0
fi

# $3 is an optional request header, passed as one argument rather than spliced
# into a command string — an embedded `-H 'Accept-Encoding: br'` would reach the
# loader with its quotes intact and be parsed as garbage.
run_load() {
    label=$1; url=$2; hdr=${3:-}
    printf '\n   %s\n' "$label"
    if [ "$LOADER" = wrk ]; then
        if [ -n "$hdr" ]; then
            wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency -H "$hdr" "$url" 2>/dev/null
        else
            wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --latency "$url" 2>/dev/null
        fi | sed -n 's/^/     /p'
    else
        if [ -n "$hdr" ]; then
            oha -z "${DURATION}s" -c "$CONNS" --insecure --ipv4 --no-tui -H "$hdr" "$url" 2>/dev/null
        else
            oha -z "${DURATION}s" -c "$CONNS" --insecure --ipv4 --no-tui "$url" 2>/dev/null
        fi | sed -n '/Summary/,/^$/p;/Latency distribution/,/^$/p' | sed 's/^/     /'
    fi
}

say "Load (this machine only — the generator shares its CPUs with the server)"
note "loader: $LOADER, ${CONNS} connections, ${THREADS} threads, ${DURATION}s per phase"

run_load "HTTPS keep-alive, 9 KB HTML (identity)" "https://localhost:$PORT_HTTPS/index.html"
run_load "HTTPS keep-alive, 9 KB HTML (brotli)"   "https://localhost:$PORT_HTTPS/index.html" \
    "Accept-Encoding: br"
run_load "HTTPS keep-alive, 180 KB JS"   "https://localhost:$PORT_HTTPS/app.js"
run_load "HTTPS keep-alive, 404"         "https://localhost:$PORT_HTTPS/nope"
run_load "HTTP  keep-alive, 301 upgrade" "http://localhost:$PORT_HTTP/index.html"

# The cost of a fresh connection: what resumption and 0-RTT exist to avoid.
#
# `openssl s_time` is the obvious tool and cannot be used here — it has no
# -servername option, so it sends no SNI and this server refuses the handshake.
# curl reports the timing breakdown instead: time_appconnect - time_connect is
# exactly the TLS handshake, TCP already established.
say "TLS handshake latency (one connection at a time — a latency figure, not throughput)"
HS_N=50
# One curl process per sample on purpose: passing N URLs to a single curl makes
# it reuse the connection, so only the first would carry a handshake at all.
: > "$WORK/handshake.txt"
i=0
while [ $i -lt $HS_N ]; do
    curl -sk --ipv4 -o /dev/null -w '%{time_connect} %{time_appconnect}\n' \
        "https://localhost:$PORT_HTTPS/tiny.txt" 2>/dev/null >> "$WORK/handshake.txt" || true
    i=$((i + 1))
done
if [ -s "$WORK/handshake.txt" ]; then
    # Do not name these $a/$b: a lexical $a shadows the one sort's comparator
    # uses, and the sort silently stops working.
    perl -ne '
        my ($tcp, $tls) = split;
        next unless $tls && $tls > $tcp;
        push @h, ($tls - $tcp) * 1000;
        END {
            @h = sort { $a <=> $b } @h;
            printf "     full handshake: min %.2f ms, median %.2f ms, p90 %.2f ms (n=%d)\n",
                $h[0], $h[int(@h/2)], $h[int(@h*0.9)], scalar(@h);
        }' "$WORK/handshake.txt"
else
    note "handshake timing unavailable"
fi

# New connection per request, as throughput. Only oha can do this; wrk always
# keeps connections alive.
if command -v oha >/dev/null 2>&1; then
    note "new connection per request (no keep-alive), ${DURATION}s:"
    oha -z "${DURATION}s" -c "$CONNS" --insecure --ipv4 --no-tui --disable-keepalive \
        "https://localhost:$PORT_HTTPS/tiny.txt" 2>/dev/null \
        | sed -n '/Summary/,/^$/p' | sed 's/^/     /' || true
fi

say "Done"
note "server log: $WORK/server.log"
