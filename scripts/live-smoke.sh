#!/bin/sh
# Opt-in live test. Requires root and a tethering phone. Always tears down.
set -eu
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo 'Run with sudo.' >&2; exit 1; fi
logdir=$(mktemp -d /tmp/android-rndis-smoke.XXXXXX)
chmod 755 "$logdir"
pid=
cleanup() {
    if [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        count=0
        while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 10 ]; do
            sleep 1
            count=$((count + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo 'FAIL: graceful shutdown exceeded 10 seconds' >&2
            kill -KILL "$pid" 2>/dev/null || true
            shutdown_failed=1
        fi
        wait "$pid" || true
        pid=
    fi
    /usr/sbin/netstat -rn -f inet > "$logdir/routes-after.txt"
    /usr/sbin/scutil --dns > "$logdir/dns-after.txt"
    chmod -R a+rX "$logdir"
    echo "Live test logs: $logdir"
    if [ "${shutdown_failed:-0}" -eq 1 ]; then exit 1; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
/usr/sbin/netstat -rn -f inet > "$logdir/routes-before.txt"
/usr/sbin/scutil --dns > "$logdir/dns-before.txt"
./build/android-rndis-macos --verbose > "$logdir/daemon.log" 2>&1 &
pid=$!
i=0
while [ "$i" -lt 30 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then cat "$logdir/daemon.log"; exit 1; fi
    if /usr/bin/grep -q 'bridging .*USB tethering' "$logdir/daemon.log"; then break; fi
    sleep 1
    i=$((i + 1))
done
if [ "$i" -eq 30 ]; then cat "$logdir/daemon.log"; exit 1; fi
iface=$(/usr/bin/sed -n 's/.*bridging \(utun[0-9]*\) <.*/\1/p' "$logdir/daemon.log")
/usr/sbin/netstat -rn -f inet > "$logdir/routes-during.txt"
/usr/sbin/scutil --dns > "$logdir/dns-during.txt"
/sbin/route -n get 1.1.1.1 > "$logdir/route-check.txt"
/usr/bin/grep -q "interface: $iface" "$logdir/route-check.txt"
/sbin/ping -c 3 -W 3000 1.1.1.1 > "$logdir/ping.txt" 2>&1 || true
/usr/bin/curl -4 --interface "$iface" --connect-timeout 10 --max-time 25 --fail --silent --show-error \
    -o /dev/null -w 'HTTPS via tether: %{http_code}, %{speed_download} B/s\n' https://example.com > "$logdir/https.txt" 2>&1
cat "$logdir/daemon.log" "$logdir/ping.txt" "$logdir/https.txt"
