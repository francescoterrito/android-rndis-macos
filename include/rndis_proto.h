/* Buffer-based port of Linux rndis_tx_fixup / rndis_rx_fixup + bind helpers.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef CABLED_HOTSPOT_RNDIS_PROTO_H
#define CABLED_HOTSPOT_RNDIS_PROTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TX: wrap one Ethernet frame in RNDIS_MSG_PACKET.
 * in: eth frame [eth, eth_len]; out: buffer [out, out_cap].
 * Returns wrapped length, or 0 on error (out_cap too small).
 * Needs out_cap >= eth_len + sizeof(struct rndis_data_hdr).
 * Direct port of Linux rndis_tx_fixup (without skb handling).
 */
size_t rndis_wrap_packet(const uint8_t *eth, size_t eth_len,
                         uint8_t *out, size_t out_cap);

/* RX: unwrap possibly-batched RNDIS buffer from bulk-IN.
 * Calls cb(eth, eth_len, ctx) once per contained Ethernet frame.
 * Returns number of frames delivered, or -1 on framing error.
 * Direct port of Linux rndis_rx_fixup validation loop.
 */
typedef void (*rndis_frame_cb)(const uint8_t *eth, size_t eth_len, void *ctx);
int rndis_unwrap_packets(const uint8_t *buf, size_t buflen,
                         rndis_frame_cb cb, void *ctx);

/* Control-plane opaqueness: implemented in usb.c with libusb. Documented here
 * so the Linux mapping is explicit:
 *   rndis_command()  <- Linux rndis_command(): SEND_ENCAPSULATED + GET_ENCAPSULATED
 *                        retry loop (10x), xid match, INDICATE + KEEPALIVE handling.
 *   rndis_query()    <- Linux rndis_query(): QUERY oid with in_len payload
 *                        (ActiveSync quirk: pad payload >= expected reply).
 *   rndis_bind_seq() <- Linux generic_rndis_bind(): INIT -> QUERY(PHYSICAL_MEDIUM)
 *                        -> QUERY(PERMANENT_ADDRESS) -> SET(PACKET_FILTER).
 */
uint32_t rndis_next_xid(void);

#ifdef __cplusplus
}
#endif

#endif
