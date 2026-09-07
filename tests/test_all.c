/* Offline unit tests: framing, ARP shim, DHCP build/parse, checksums.
 * No USB hardware needed. Run with `make test`.
 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "rndis.h"
#include "rndis_proto.h"
#include "frame.h"
#include "dhcp.h"
#include "usb.h"
#include "net_util.h"

int g_verbose = 0;
/* Stubs: dhcp_run (USB I/O) is not exercised offline. */
int usb_bulk_out(struct rndis_usb_dev *d, const uint8_t *b, size_t l,
                 unsigned t) {
    (void)d;
    (void)b;
    (void)l;
    (void)t;
    return -1;
}
int usb_bulk_in(struct rndis_usb_dev *d, uint8_t *b, size_t c, size_t *g,
                unsigned t) {
    (void)d;
    (void)b;
    (void)c;
    (void)g;
    (void)t;
    return -1;
}

static int fails = 0;
#define CHECK(c, msg) do { \
    if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); fails++; } \
    else { printf("ok %s\n", msg); } \
} while (0)

static void cb_count(const uint8_t *eth, size_t len, void *ctx) {
    (void)eth;
    int *n = ctx;
    (*n)++;
    int *total = (int *)(((char *)ctx) + sizeof(int));
    *total += (int)len;
}

int main(void) {
    /* 1. wrap/unwrap roundtrip */
    uint8_t eth[100];
    memset(eth, 0, sizeof(eth));
    memcpy(eth, "\x02\x00\x00\x00\x00\x02", 6);
    memcpy(eth + 6, "\x02\x00\x00\x00\x00\x01", 6);
    eth[12] = 0x08;
    eth[13] = 0x00;
    for (int i = 14; i < 100; i++) eth[i] = (uint8_t)i;
    uint8_t wrapped[256];
    size_t wl = rndis_wrap_packet(eth, sizeof(eth), wrapped, sizeof(wrapped));
    CHECK(wl == sizeof(eth) + 44, "wrap len = eth+44");
    CHECK(wrapped[0] == 1 && wrapped[1] == 0, "wrap msg type PACKET");
    int n = 0, total = 0;
    int ctx[2] = {0, 0};
    (void)n;
    (void)total;
    int got = rndis_unwrap_packets(wrapped, wl, cb_count, ctx);
    CHECK(got == 1 && ctx[0] == 1 && ctx[1] == 100, "unwrap single");

    /* batched: two packets in one bulk buffer */
    uint8_t batch[512];
    memcpy(batch, wrapped, wl);
    memcpy(batch + wl, wrapped, wl);
    ctx[0] = ctx[1] = 0;
    got = rndis_unwrap_packets(batch, wl * 2, cb_count, ctx);
    CHECK(got == 2 && ctx[0] == 2, "unwrap batched x2");

    /* truncated -> 0 frames, no crash */
    ctx[0] = ctx[1] = 0;
    got = rndis_unwrap_packets(batch, wl - 1, cb_count, ctx);
    CHECK(got == 0, "unwrap truncated");

    /* 2. checksum sanity: known IP header */
    uint8_t iph[20] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                       0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
                       0xc0, 0xa8, 0x00, 0xc7};
    uint16_t c = ip_checksum(iph, 20);
    CHECK(c == 0x9c5d, "ip checksum rfc example");

    /* 3. frame shim: init, wrap, handle */
    uint8_t our_mac[6] = {0x02, 1, 2, 3, 4, 5};
    uint8_t our_ip[4] = {192, 168, 42, 100};
    uint8_t gw_ip[4] = {192, 168, 42, 129};
    uint8_t gw_mac[6] = {0x02, 9, 9, 9, 9, 9};
    frame_init(our_mac, our_ip);
    frame_set_peer(gw_mac, gw_ip);
    uint8_t ip[20];
    memset(ip, 0, sizeof(ip));
    ip[0] = 0x45;
    uint8_t eout[1600];
    size_t el = frame_wrap_out(ip, sizeof(ip), eout, sizeof(eout));
    CHECK(el == 34 && !memcmp(eout, gw_mac, 6), "frame wrap dst=peer");

    /* inbound ARP request for us -> reply (fully specified packet: no
     * uninitialized bytes, sanitizer builds fill stack with garbage). */
    uint8_t arp_req[42];
    memset(arp_req, 0, sizeof(arp_req));
    memset(arp_req, 0xff, 6);
    memcpy(arp_req + 6, gw_mac, 6);
    arp_req[12] = 0x08;
    arp_req[13] = 0x06;
    struct arp_pkt *a = (struct arp_pkt *)(arp_req + 14);
    a->htype[0] = 0;
    a->htype[1] = 1;
    a->ptype[0] = 0x08;
    a->ptype[1] = 0x00;
    a->hlen = 6;
    a->plen = 4;
    a->oper[0] = 0;
    a->oper[1] = 1;
    memcpy(a->sha, gw_mac, 6);
    memcpy(a->spa, gw_ip, 4);
    memcpy(a->tpa, our_ip, 4);
    uint8_t ipout[1500], rep[1600];
    size_t rlen = 0;
    int r = frame_handle_in(arp_req, sizeof(arp_req), ipout, sizeof(ipout),
                            rep, sizeof(rep), &rlen);
    CHECK(r == 0 && rlen == 42 && rep[12] == 0x08 && rep[13] == 0x06,
          "arp request answered");

    /* inbound IP -> utun payload */
    uint8_t eth_ip[14 + 20];
    memcpy(eth_ip, our_mac, 6);
    memcpy(eth_ip + 6, gw_mac, 6);
    eth_ip[12] = 0x08;
    eth_ip[13] = 0x00;
    memset(eth_ip + 14, 0, 20);
    eth_ip[14] = 0x45;
    put_be16(eth_ip + 16, 20);
    rlen = 0;
    r = frame_handle_in(eth_ip, sizeof(eth_ip), ipout, sizeof(ipout), rep,
                        sizeof(rep), &rlen);
    CHECK(r == 1 && ipout[0] == 0x45, "ip passed to utun");

    /* 4. DHCP build/parse roundtrip */
    uint8_t deth[1600];
    uint32_t xid = 0xdeadbeef;
    size_t dl = dhcp_build_discover(our_mac, xid, deth, sizeof(deth));
    CHECK(dl > 300 && deth[12] == 0x08, "dhcp discover built");

    /* craft fake OFFER by hand: reuse discover then patch op/xid/options */
    /* Simpler: build ACK-like reply via raw bytes and parse with same xid. */
    uint8_t offer[600];
    memset(offer, 0, sizeof(offer));
    memcpy(offer, our_mac, 6);
    memcpy(offer + 6, gw_mac, 6);
    offer[12] = 0x08;
    offer[13] = 0x00;
    uint8_t *oip = offer + 14;
    oip[0] = 0x45;
    oip[9] = 17;
    size_t oihl = 20;
    uint8_t *oudp = oip + oihl;
    put_be16(oudp, 67);
    put_be16(oudp + 2, 68);
    struct dhcp_fixed *d = (struct dhcp_fixed *)(oudp + 8);
    d->op = 2;
    d->htype = 1;
    d->hlen = 6;
    d->xid[0] = 0xde;
    d->xid[1] = 0xad;
    d->xid[2] = 0xbe;
    d->xid[3] = 0xef;
    memcpy(d->yiaddr, our_ip, 4);
    memcpy(d->chaddr, our_mac, 6);
    d->magic[0] = 99;
    d->magic[1] = 130;
    d->magic[2] = 83;
    d->magic[3] = 99;
    uint8_t *oo = (uint8_t *)d + sizeof(*d);
    *oo++ = 53;
    *oo++ = 1;
    *oo++ = 2;
    *oo++ = 1;
    *oo++ = 4;
    memcpy(oo, "\xff\xff\xff\x00", 4);
    oo += 4;
    *oo++ = 3;
    *oo++ = 4;
    memcpy(oo, gw_ip, 4);
    oo += 4;
    *oo++ = 6;
    *oo++ = 8;
    memcpy(oo, gw_ip, 4);
    oo += 4;
    memcpy(oo, "\x08\x08\x08\x08", 4);
    oo += 4;
    *oo++ = 54;
    *oo++ = 4;
    memcpy(oo, gw_ip, 4);
    oo += 4;
    *oo++ = 255;
    size_t offer_len = (size_t)(oo - offer);
    /* fix lengths */
    put_be16(oip + 2, (uint16_t)(offer_len - 14));
    put_be16(oudp + 4, (uint16_t)(offer_len - 14 - oihl));
    int mt = 0;
    struct dhcp_result res;
    uint8_t pm[6];
    int pr = dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm);
    CHECK(pr == 0 && mt == 2 && !memcmp(res.ip, our_ip, 4), "dhcp offer parsed");
    CHECK(!memcmp(res.gw, gw_ip, 4), "dhcp gw parsed");
    CHECK(res.have_dns2 && !memcmp(res.dns2, "\x08\x08\x08\x08", 4),
          "dhcp second dns parsed");

    /* Malformed lengths must not use Ethernet padding as DHCP options. */
    put_be16(oudp + 4, 8 + sizeof(*d));
    CHECK(dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm) == -1,
          "DHCP ignores options beyond UDP length");
    put_be16(oudp + 4, (uint16_t)(offer_len - 34));
    oip[0] = 0x44;
    CHECK(dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm) == -1,
          "DHCP rejects IHL below 20");
    oip[0] = 0x45;
    put_be16(oip + 6, 0x2000);
    CHECK(dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm) == -1,
          "DHCP rejects fragmented datagrams");
    put_be16(oip + 6, 0);
    /* Server identifier and router are independent (RFC 2131). */
    memcpy(oo - 5, "\x0a\x00\x00\x01", 4);
    CHECK(dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm) == 0 &&
          !memcmp(res.server, "\x0a\x00\x00\x01", 4) && !memcmp(res.gw, gw_ip, 4),
          "DHCP server identifier retained separately from router");
    oo[-1] = 99;
    CHECK(dhcp_parse_reply(offer, offer_len, xid, &mt, &res, pm) == -1,
          "DHCP rejects truncated option");
    oo[-1] = 255;

    CHECK(rndis_wrap_packet(eth, SIZE_MAX, wrapped, sizeof(wrapped)) == 0,
          "RNDIS wrap rejects size overflow");
    struct rndis_data_hdr *rh = (struct rndis_data_hdr *)wrapped;
    rh->data_offset = htole32(0);
    CHECK(rndis_unwrap_packets(wrapped, wl, cb_count, ctx) == -1,
          "RNDIS rejects data overlapping header");
    rh->data_offset = htole32(UINT32_MAX);
    CHECK(rndis_unwrap_packets(wrapped, wl, cb_count, ctx) == -1,
          "RNDIS rejects overflowing data offset");

    uint8_t padded[60] = {0};
    memcpy(padded, eth_ip, sizeof(eth_ip));
    memset(ipout, 0xaa, sizeof(ipout));
    CHECK(frame_handle_in(padded, sizeof(padded), ipout, sizeof(ipout), rep,
                          sizeof(rep), &rlen) == 1 && ipout[20] == 0xaa,
          "Ethernet padding excluded from IPv4 payload");
    padded[14] = 0x41;
    CHECK(frame_handle_in(padded, sizeof(padded), ipout, sizeof(ipout), rep,
                          sizeof(rep), &rlen) == -1, "invalid IPv4 header rejected");
    CHECK(frame_wrap_out(ip, SIZE_MAX, eout, sizeof(eout)) == 0,
          "Ethernet wrap rejects size overflow");
    uint8_t before[6], after[6];
    frame_get_peer(before, NULL);
    memset(padded + 6, 0xff, 6);
    padded[12] = 0x86; padded[13] = 0xdd;
    frame_handle_in(padded, sizeof(padded), ipout, sizeof(ipout), rep, sizeof(rep), &rlen);
    frame_get_peer(after, NULL);
    CHECK(!memcmp(before, after, 6), "unknown EtherType cannot poison peer MAC");

    uint8_t new_gw_ip[4] = {192, 168, 42, 1};
    uint8_t new_gw_mac[6] = {0x02, 8, 8, 8, 8, 8};
    uint8_t bcast[6];
    memset(bcast, 0xff, 6);
    frame_set_peer(bcast, new_gw_ip);
    uint8_t arpq[42];
    CHECK(frame_build_arp_request(arpq, sizeof(arpq)) == 42 &&
          !memcmp(arpq + 38, new_gw_ip, 4),
          "ARP request queries the updated gateway");
    el = frame_wrap_out(ip, sizeof(ip), eout, sizeof(eout));
    CHECK(el == 34 && !memcmp(eout, bcast, 6),
          "unresolved gateway uses broadcast destination");
    uint8_t arp_rep[42];
    memset(arp_rep, 0, sizeof(arp_rep));
    memcpy(arp_rep, our_mac, 6);
    memcpy(arp_rep + 6, new_gw_mac, 6);
    arp_rep[12] = 0x08;
    arp_rep[13] = 0x06;
    struct arp_pkt *ar = (struct arp_pkt *)(arp_rep + 14);
    ar->htype[1] = 1;
    ar->ptype[0] = 0x08;
    ar->hlen = 6;
    ar->plen = 4;
    ar->oper[1] = 2;
    memcpy(ar->sha, new_gw_mac, 6);
    memcpy(ar->spa, new_gw_ip, 4);
    memcpy(ar->tha, our_mac, 6);
    memcpy(ar->tpa, our_ip, 4);
    rlen = 0;
    r = frame_handle_in(arp_rep, sizeof(arp_rep), ipout, sizeof(ipout),
                        rep, sizeof(rep), &rlen);
    uint8_t learned[6];
    frame_get_peer(learned, NULL);
    CHECK(r == 0 && rlen == 0 && !memcmp(learned, new_gw_mac, 6),
          "ARP reply learns the new gateway MAC");
    el = frame_wrap_out(ip, sizeof(ip), eout, sizeof(eout));
    CHECK(el == 34 && !memcmp(eout, new_gw_mac, 6),
          "resolved gateway used as Ethernet destination");

    /* Three full-MTU packets fit the Samsung limit; a fourth remains unread. */
    uint8_t large_eth[1514] = {0}, multi[4740], snapshot[4740];
    struct rndis_batch rb;
    rndis_batch_init(&rb, multi, sizeof(multi), 3, 1);
    for (int i = 0; i < 3; i++) {
        large_eth[20] = (uint8_t)i;
        CHECK(rndis_batch_append(&rb, large_eth, sizeof(large_eth)) == 0,
              "negotiated batch accepts full-MTU packet");
    }
    memcpy(snapshot, multi, rb.len);
    CHECK(rb.len == 4674 && rndis_batch_reserve(&rb, 1514) == NULL &&
          rndis_batch_append(&rb, large_eth, sizeof(large_eth)) == -1 &&
          !memcmp(snapshot, multi, rb.len), "full batch refuses next packet without mutation");
    ctx[0]=ctx[1]=0;
    CHECK(rndis_unwrap_packets(multi, rb.len, cb_count, ctx) == 3 && ctx[1] == 4542,
          "full-MTU batch decodes all three packets");
    rndis_batch_init(&rb, multi, sizeof(multi), 2, 128);
    CHECK(rndis_batch_append(&rb, eth, 100) == 0 &&
          rndis_batch_append(&rb, eth, 100) == 0 && rb.last == 256 && rb.len == 400,
          "negotiated 128-byte alignment pads preceding message");
    ctx[0]=ctx[1]=0;
    CHECK(rndis_unwrap_packets(multi, rb.len, cb_count, ctx) == 2,
          "aligned batch decodes without losing padding boundaries");
    rndis_batch_init(&rb, multi, sizeof(multi), 1, 8);
    uint8_t *inplace = rndis_batch_reserve(&rb, sizeof(eth));
    memcpy(inplace, eth, sizeof(eth));
    CHECK(rndis_batch_append(&rb, inplace, sizeof(eth)) == 0 &&
          rndis_batch_reserve(&rb, sizeof(eth)) == NULL,
          "in-place batch encoding honors a one-packet device");

    if (fails == 0)
        printf("\nALL TESTS PASSED\n");
    else
        printf("\n%d FAILURES\n", fails);
    return fails != 0;
}
