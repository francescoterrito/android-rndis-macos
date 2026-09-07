#!/bin/sh
# Opt-in hardware test; manual SIGUSR1 requests an early RFC 2131 renewal.
set -eu
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo 'Run with sudo.' >&2; exit 1; }
logdir=$(mktemp -d /tmp/android-rndis-renew.XXXXXX)
chmod 755 "$logdir"
pid=; loadpid=; pingpid=
cleanup() {
    [ -z "$loadpid" ] || { kill "$loadpid" 2>/dev/null || true; wait "$loadpid" 2>/dev/null || true; }
    [ -z "$pingpid" ] || { kill "$pingpid" 2>/dev/null || true; wait "$pingpid" 2>/dev/null || true; }
    failed=0
    if [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 1; i=$((i+1)); done
        if kill -0 "$pid" 2>/dev/null; then failed=1; kill -KILL "$pid"; fi
        wait "$pid" || failed=1
    fi
    /usr/sbin/scutil --dns > "$logdir/dns-after.txt"
    /usr/sbin/netstat -rn -f inet > "$logdir/routes-after.txt"
    chmod -R a+rX "$logdir"
    echo "Renewal logs: $logdir"
    [ "$failed" -eq 0 ] || { echo 'FAIL graceful shutdown' >&2; exit 1; }
}
trap cleanup EXIT
trap 'exit 130' INT TERM
/usr/sbin/scutil --dns > "$logdir/dns-before.txt"
/usr/sbin/netstat -rn -f inet > "$logdir/routes-before.txt"
./build/android-rndis-macos --verbose > "$logdir/daemon.log" 2>&1 &
pid=$!
i=0
while ! grep -q 'bridging .*USB tethering' "$logdir/daemon.log"; do
    kill -0 "$pid" 2>/dev/null || { cat "$logdir/daemon.log"; exit 1; }
    i=$((i+1)); [ "$i" -lt 20 ] || { cat "$logdir/daemon.log"; exit 1; }; sleep 1
done
iface=$(sed -n 's/.*bridging \(utun[0-9]*\) <.*/\1/p' "$logdir/daemon.log")
cp /tmp/android-rndis-macos-status.json "$logdir/status-start.json"
/usr/bin/curl -4 --interface "$iface" --limit-rate 64K --max-time 35 --fail --silent --show-error \
    -o /dev/null -w 'HTTPS across renewals: %{http_code}, %{size_download} bytes in %{time_total}s\n' \
    'https://speed.cloudflare.com/__down?bytes=1048576' > "$logdir/download.txt" 2>&1 &
loadpid=$!
/sbin/ping -c 15 -t 20 -W 2000 1.1.1.1 > "$logdir/ping.txt" 2>&1 &
pingpid=$!
for count in 1 2 3; do
    sleep 2
    kill -USR1 "$pid"
    i=0
    while ! grep -q "DHCP renewed in place ($count)" "$logdir/daemon.log"; do
        kill -0 "$pid" 2>/dev/null || { cat "$logdir/daemon.log"; exit 1; }
        i=$((i+1)); [ "$i" -lt 10 ] || { cat "$logdir/daemon.log"; exit 1; }; sleep 1
    done
done
wait "$loadpid"; loadpid=
wait "$pingpid"; pingpid=
cp /tmp/android-rndis-macos-status.json "$logdir/status-end.json"
[ "$(grep -c 'bridging .*USB tethering' "$logdir/daemon.log")" -eq 1 ]
cat "$logdir/daemon.log" "$logdir/download.txt" "$logdir/ping.txt" "$logdir/status-end.json"
