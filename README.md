# android-rndis-macos

Userspace Android USB tethering (RNDIS) driver for macOS. No kext, no SIP change.

```
Android (RNDIS) <--> USB/libusb <--> cabled-hotspot <--> utun <--> macOS networking
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
src/rndis.c            portable framing + bind helpers
src/usb.c / usb.h      libusb matching, claim, control/bulk endpoints
src/utun.c / utun.h    macOS utun via PF_SYSTEM + ifconfig
src/frame.c            Ethernet <-> utun conversion + ARP + peer learning
src/dhcp.c             minimal DHCP client (DISCOVER/OFFER/REQUEST/ACK)
src/net_util.c         checksums, BE helpers
src/route.c            split-default routes + DNS via scutil, full restore
src/main.c             orchestration: usb -> rndis_init -> DHCP -> utun -> bridge
tests/test_all.c       offline unit tests (no hardware needed)
```

## Build + verify (no phone needed)

```sh
brew install libusb
make
make test          # 13 checks: framing, ARP, DHCP, checksums
make san           # same tests under ASan+UBSan
make fuzz          # 190k deterministic fuzz iterations over all parsers
./build/cabled-hotspot --probe   # with phone: INIT/QUERY, prints MAC
```

## Use with phone

```sh
# 1. Android: Settings > Hotspot & tethering > USB tethering ON (data cable!)
# 2. Mac:
sudo ./build/cabled-hotspot --verbose
# options: --watch (auto-reconnect), --no-route, --no-dns,
#          --static 192.168.42.50 --gateway 192.168.42.129
#          --netmask 255.255.255.0 --dns 8.8.8.8 --verbose
```

Status: builds warning-free on arm64, `make test` passes.
Handshake verified live against Samsung 04e8:6863 (INIT/DHCP/utun/DNS all
confirmed working end-to-end with ping + browsing).

Performance design (v2): async libusb pipeline — 16 RX transfers permanently
in flight on a dedicated event thread, 32 TX slots with up to 4 Ethernet
frames batched per USB transfer (bounded by the device's max_transfer_size),
4MB utun socket buffers, non-blocking I/O throughout. Throughput ceiling is
the USB bus / carrier, not per-transfer round trips.

## License

GPL-2.0-or-later (inherited from Linux `rndis_host.c` port). See `include/rndis.h`.
