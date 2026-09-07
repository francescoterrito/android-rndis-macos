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

    if (fails == 0)
        printf("\nALL TESTS PASSED\n");
    else
        printf("\n%d FAILURES\n", fails);
    return fails != 0;
}
