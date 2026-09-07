/* SPDX-License-Identifier: GPL-2.0-or-later
 * Port of Linux drivers/net/usb/rndis_host.c framing logic to plain buffers.
 */
#include "rndis.h"
#include "rndis_proto.h"
#include <string.h>
#include <stdatomic.h>

static atomic_uint g_xid = 1;

uint32_t rndis_next_xid(void) {
    uint32_t id = atomic_fetch_add(&g_xid, 1);
    if (id == 0) id = atomic_fetch_add(&g_xid, 1);
    return id;
}

size_t rndis_wrap_packet(const uint8_t *eth, size_t eth_len,
                         uint8_t *out, size_t out_cap) {
    /* Linux: hdr->msg_type = RNDIS_MSG_PACKET; msg_len = skb->len;
     * data_offset = sizeof(*hdr) - 8 (=36); data_len = eth len. */
    if (!eth || !out) return 0;
    if (out_cap < sizeof(struct rndis_data_hdr) ||
        eth_len > out_cap - sizeof(struct rndis_data_hdr) ||
        eth_len > UINT32_MAX - sizeof(struct rndis_data_hdr)) return 0;

    struct rndis_data_hdr *hdr = (struct rndis_data_hdr *)out;
    memset(hdr, 0, sizeof(*hdr));
    hdr->msg_type = htole32(RNDIS_MSG_PACKET);
    hdr->msg_len = htole32((uint32_t)(sizeof(*hdr) + eth_len));
    hdr->data_offset = htole32((uint32_t)(sizeof(*hdr) - 8));
    hdr->data_len = htole32((uint32_t)eth_len);
    if (eth != out + sizeof(*hdr)) memcpy(out + sizeof(*hdr), eth, eth_len);
    return sizeof(*hdr) + eth_len;
}

int rndis_unwrap_packets(const uint8_t *buf, size_t buflen,
                         rndis_frame_cb cb, void *ctx) {
    /* Linux rndis_rx_fixup: walk batched RNDIS_MSG_PACKETs, validate
     * msg_len / data_offset / data_len with overflow checks. */
    int delivered = 0;
    size_t off = 0;

    while (buflen - off >= sizeof(struct rndis_data_hdr)) {
        const struct rndis_data_hdr *hdr =
            (const struct rndis_data_hdr *)(buf + off);
        uint32_t msg_type = le32toh(hdr->msg_type);
        uint32_t msg_len = le32toh(hdr->msg_len);
        uint32_t data_offset = le32toh(hdr->data_offset);
        uint32_t data_len = le32toh(hdr->data_len);

        if (msg_type != RNDIS_MSG_PACKET) break; /* INDICATE etc. handled on control plane */
        if (msg_len < sizeof(*hdr)) return -1;
        if (msg_len > buflen - off) break; /* partial batch: wait for more USB data */

        size_t hdr_end, data_end;
        if (__builtin_add_overflow(off, (size_t)8 + data_offset, &hdr_end)) return -1;
        if (__builtin_add_overflow(hdr_end, data_len, &data_end)) return -1;
        if (data_offset < sizeof(*hdr) - 8 || data_len < 14 ||
            data_end > off + msg_len) return -1;

        if (cb) cb(buf + hdr_end, data_len, ctx);
        delivered++;

        off += msg_len;
        /* Linux notes devices may zero-pad to end-of-packet; bulk transfer
         * already frames this, so trailing zeros are ignored by caller. */
        if (off == buflen) break;
    }
    return delivered;
}

void rndis_batch_init(struct rndis_batch *b, uint8_t *buf, size_t cap,
                       unsigned max_packets, unsigned alignment) {
    *b = (struct rndis_batch){.buf = buf, .cap = cap,
        .max_packets = max_packets, .alignment = alignment};
}
uint8_t *rndis_batch_reserve(struct rndis_batch *b, size_t eth_len) {
    if (!b->alignment || b->alignment > 128 ||
        (b->alignment & (b->alignment - 1)) ||
        b->packets >= b->max_packets || b->len > b->cap) return NULL;
    size_t pad = (-(size_t)b->len) & (b->alignment - 1);
    if (pad > b->cap - b->len || sizeof(struct rndis_data_hdr) > b->cap - b->len - pad ||
        eth_len > b->cap - b->len - pad - sizeof(struct rndis_data_hdr)) return NULL;
    return b->buf + b->len + pad + sizeof(struct rndis_data_hdr);
}
int rndis_batch_append(struct rndis_batch *b, const uint8_t *eth, size_t len) {
    uint8_t *payload = rndis_batch_reserve(b, len);
    if (!payload) return -1;
    size_t start = (size_t)(payload - b->buf) - sizeof(struct rndis_data_hdr);
    size_t n = rndis_wrap_packet(eth, len, b->buf + start, b->cap - start);
    if (!n) return -1;
    if (b->packets) {
        struct rndis_data_hdr *prev = (struct rndis_data_hdr *)(b->buf + b->last);
        memset(b->buf + b->len, 0, start - b->len);
        prev->msg_len = htole32((uint32_t)(start - b->last));
    }
    b->last = start; b->len = start + n; b->packets++;
    return 0;
}
