# android-rndis-macos

Userspace Android USB tethering (RNDIS) driver for macOS. No kext, no SIP change.

```
Android (RNDIS) <--> USB/libusb <--> android-rndis-macos <--> utun <--> macOS networking
```

## Why userspace?

macOS ships no RNDIS driver. The old HoRNDIS kext is dead on Apple Silicon /
Ventura+. The modern approach (used by DroidTether, android-usb-tether-macos,
rndis-mac) is a plain daemon: speak RNDIS over `libusb`, bridge to a `utun`
interface via `PF_SYSTEM / SYSPROTO_CONTROL`.

## What is reused from Linux?

Ported from `drivers/net/usb/rndis_host.c`,
`include/linux/usb/rndis_host.h`, `include/linux/rndis.h` (GPL-2.0-or-later,
Copyright (C) 2005 David Brownell):

Reusable verbatim (pure protocol, in `include/rndis.h` + `src/rndis.c`):

* All `RNDIS_MSG_*`, `RNDIS_STATUS_*`, `RNDIS_OID_*`, `RNDIS_PACKET_TYPE_*` constants
* All message structs (`rndis_init`, `rndis_query`, `rndis_set`, `rndis_data_hdr`, ...)
* `CONTROL_BUFFER_SIZE` (1025), `RNDIS_CONTROL_TIMEOUT_MS` (5000)
* Bind sequence: `INIT(1.0)` -> `QUERY(PHYSICAL_MEDIUM)` -> `QUERY(802_3_PERMANENT_ADDRESS)` -> `SET(CURRENT_PACKET_FILTER = RNDIS_DEFAULT_FILTER)`
* `rndis_tx_fixup`: prepend 44-byte `RNDIS_MSG_PACKET` header (`data_offset = 36`)
* `rndis_rx_fixup`: strip header, handle batched packets, overflow checks
* Quirks: `POLL_STATUS` (poll interrupt EP before control-IN), `DST_MAC_FIXUP` (ZTE),
  ActiveSync query payload padding

NOT reusable (Linux-kernel-only, rewritten here):

* `usbnet`, `net_device`, `sk_buff`, `urb`, `usb_driver` probe/disconnect, ethtool, PM
* Replaced by: `src/usb.c` (libusb discovery/claim + control/bulk transfers),
  `src/utun.c` (utun bring-up), `src/dhcp.c` + `src/frame.c`
  (Ethernet<->utun L2/L3 shim with ARP handling, DHCP client, route/DNS via `ifconfig`/`route`/`scutil`).

Device match table in `src/usb.c` mirrors Linux `products[]`:
`COMM/2/0xff`, `WIRELESS/1/3`, `MISC/1/1`, `MISC/4/1`, plus ZTE `0x19d2` and 2Wire `0x1630/0x0042`.

## Layout

```
include/rndis.h        ported protocol structs + constants (GPL, attrib Linux)
include/rndis_proto.h  tx/rx fixup + control-plane API (buffer-based, no skb)
src/rndis.c            portable framing + negotiated multi-message TX builder
src/usb.c / usb.h      libusb matching, claim, control/bulk, USB short-packet pad
src/utun.c / utun.h    macOS utun via PF_SYSTEM + ifconfig
src/frame.c            Ethernet <-> utun conversion + ARP + peer learning
src/dhcp.c             DHCP client with in-place T1/T2 renewal and rebinding
src/net_util.c         checksums, BE helpers, sleep-aware clock
src/route.c            interface routes + session-owned SystemConfiguration DNS
src/main.c             orchestration: usb -> rndis_init -> DHCP -> utun -> bridge
src/status.c           JSON status for the menu bar app
tests/                 offline unit tests (no hardware needed)
scripts/live-smoke.sh  opt-in privileged connectivity test
scripts/live-renewal.sh  opt-in privileged in-place DHCP renewal test
```

## Build and check

```sh
brew install libusb
make app
make check        # unit tests, ASan/UBSan, deterministic fuzz and USB fault injection
```

`make check` covers framing, DHCP lease timers, utun vectored I/O, USB
allocation/submit/cancel/stall faults, and stop-signal inheritance. It does
not require a phone.

## Menu app

```sh
sudo make install
open build/AndroidRNDIS.app
```

Enable USB tethering on the phone, then choose **Turn on** in the menu.
Starting the system service asks for administrator authentication. The menu
reports startup errors and shows connecting, waiting for phone, or connected.
**Turn off** and **Turn off & Quit** stop the daemon and remove its network
settings. Starting again explicitly kickstarts the existing launchd job.
The job is loaded without running at boot; only an explicit start runs the
daemon. A crashed process can be started again from the menu. An admin
prompt may be needed each time the stopped service is started.

Build the app before installing; the menu app can also be copied to
`/Applications`. `sudo make uninstall` removes the daemon and launchd plist.

## Command line and phone diagnostics

```sh
./build/android-rndis-macos --probe --verbose  # USB handshake; no Mac network changes
make probe-dhcp                              # opt-in USB + DHCP diagnostic
sudo ./build/android-rndis-macos --verbose
sudo ./build/android-rndis-macos --watch      # retry after a lost session
sudo sh scripts/live-smoke.sh                # temporary routes, DNS, ping and HTTPS test
sudo sh scripts/live-renewal.sh              # three SIGUSR1 renewals during HTTPS + ping
```

Options include `--no-route`, `--no-dns`, `--static IP`, `--gateway IP`,
`--netmask IP`, `--dns IP`, and `--single-tx` (one Ethernet frame per USB
transfer, for comparison). The menu's off flag applies to `--watch`;
a manual foreground connection can be stopped with Ctrl-C. `SIGUSR1` asks
the running daemon to renew its DHCP lease immediately. Only one network
daemon can run at a time. Stop it before running USB diagnostics.

DHCP failure leaves the Mac network unchanged. Split-default routes use the
utun interface and DNS uses session-owned SystemConfiguration service keys;
closing the tunnel or losing the process removes those resources. The
existing global DNS dictionary is never overwritten. Conflicting split
routes cause setup to fail and roll back.

Status is written to `/tmp/android-rndis-macos-status.json`. Besides the
menu fields (`state`, `ip`, `ifname`, byte/packet counters, uptime), it
includes `tx_transfers`, `tx_errors`, `tx_drops`, `rx_drops`,
`dhcp_renewals`, and `lease_remaining_sec`.

## Data path

The transport keeps 16 asynchronous RX transfers and 32 asynchronous TX
slots in flight. After RNDIS INIT the daemon honors the device's maximum
transfer size, packets per transfer, and alignment. Outbound packets are
read from utun only when a full MTU Ethernet frame still fits, so a batch
cannot overflow and drop a packet that was already dequeued.

USB bulk OUT lengths that are an exact multiple of the endpoint's
`wMaxPacketSize` get a one-byte zero terminator, as required by the RNDIS
USB short-packet rule. That extra byte is not part of the RNDIS
`MessageLength`.

The RNDIS permanent-address query is the **host** Ethernet address. The
phone/gateway MAC comes from DHCP and ARP. If DHCP reports a new gateway
on renewal, outbound frames use the broadcast destination until ARP
resolves the new MAC.

On a typical cellular tether, several outbound packets are rarely queued
at once, so negotiated batching may not improve throughput. It is still
the default because it matches what the device advertised and adds no
aggregation delay. `--single-tx` disables it for A/B tests.

## DHCP

The initial DISCOVER/REQUEST/ACK exchange uses synchronous USB transfers
before the utun interface exists. After that, RFC 2131 T1/T2 timers drive
in-place renewal:

* T1: unicast DHCPREQUEST with `ciaddr` set, no requested-IP or server-ID options
* T2: broadcast rebind; a new server is accepted
* ACK keeps the existing utun, routes, and DNS unless mask, gateway, or DNS changed
* NAK, a different assigned address, or expiry tears the session down so
  watch mode can reacquire

Lease timers use `mach_continuous_time`, so time spent asleep counts
against T1/T2. Infinite leases are left bound. A DHCP/ARP TX pool is
reserved so data bursts cannot starve control traffic.

## Verified behavior and limits

This revision also keeps earlier fixes for startup/restart, route cleanup,
USB cancellation lifetime, parser bounds, and shared peer-state races.

Hardware checks on a Samsung `04e8:6863` tether have covered ICMP at
several sizes (including a full 1500-byte IP packet), HTTPS, and three
in-place DHCP renewals without restarting utun. Cellular throughput is
noisy; do not treat a single download as a speedup claim.

IPv4 only. Existing IPv6 connectivity can still use Wi-Fi. Sleep/wake,
physical unplug/replug, expired-lease recovery under USB faults, and other
phone models still need broader testing. The userspace bridge can drop
packets if a utun read is truncated or a TX slot cannot be submitted; it
does not promise lossless transport.

If the phone's tethering session gets stuck (ARP and DHCP succeed but
ordinary IPv4 does not), toggle USB tethering off and on on the phone.
That has cleared the condition; the driver does not currently detect or
reset it.

## License

GPL-2.0-or-later (inherited from Linux `rndis_host.c` port). See `include/rndis.h`.
