/* Deterministic fuzz for the untrusted-input parsers (run under ASan+UBSan
 * via `make fuzz`). Any out-of-bounds read/write or UB aborts the run.
 * Fixed seed => reproducible. No USB hardware needed.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "rndis.h"
#include "rndis_proto.h"
#include "frame.h"
#include "dhcp.h"
#include "usb.h"
#include "net_util.h"

int g_verbose = 0;
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

/* xorshift64, fixed seed */
static uint64_t rng = 0x123456789abcdefULL;
static uint64_t next_rand(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void rand_fill(uint8_t *p, size_t n) {
    while (n >= 8) {
        uint64_t v = next_rand();
        memcpy(p, &v, 8);
        p += 8;
        n -= 8;
    }
    if (n) {
        uint64_t v = next_rand();
        memcpy(p, &v, n);
    }
}

static void count_cb(const uint8_t *eth, size_t len, void *ctx) {
    (void)eth;
    (void)len;
    (*(int *)ctx)++;
}

int main(void) {
    static uint8_t buf[70000];
    static uint8_t out[70000];
    static uint8_t ipout[66000];
    static uint8_t reply[2048];
    uint8_t our_mac[6] = {0x02, 1, 2, 3, 4, 5};
    uint8_t our_ip[4] = {192, 168, 42, 100};
    long total = 0;

    frame_init(our_mac, our_ip);

    /* 1. pure garbage into the RNDIS unwrapper */
    for (int i = 0; i < 60000; i++) {
        size_t len = (size_t)(next_rand() % sizeof(buf));
        rand_fill(buf, len);
        int n = 0;
        (void)rndis_unwrap_packets(buf, len, count_cb, &n);
        total++;
    }

    /* 2. mutated valid wrapped packets (bit flips + truncations) */
    uint8_t eth[1500];
    rand_fill(eth, sizeof(eth));
    memcpy(eth, "\x02\xaa\xbb\xcc\xdd\xee", 6);
    memcpy(eth + 6, our_mac, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;
    size_t wl = rndis_wrap_packet(eth, sizeof(eth), out, sizeof(out));
    for (int i = 0; i < 30000; i++) {
        static uint8_t mut[2048];
        size_t mlen = wl;
        if (next_rand() & 1) mlen = (size_t)(next_rand() % (wl + 1));
        memcpy(mut, out, mlen);
        int flips = 1 + (int)(next_rand() % 6);
        for (int f = 0; f < flips && mlen; f++)
            mut[next_rand() % mlen] ^= (uint8_t)(1 << (next_rand() % 8));
        int n = 0;
        (void)rndis_unwrap_packets(mut, mlen, count_cb, &n);
        total++;
    }

    /* 3. mutated DHCP offers */
    uint8_t deth[1600];
    size_t dl = dhcp_build_discover(our_mac, 0xdeadbeef, deth, sizeof(deth));
    (void)dl;
    /* build a valid offer-ish frame then mutate it */
    uint8_t offer[700];
    memset(offer, 0, sizeof(offer));
    memcpy(offer + 6, our_mac, 6);
    offer[12] = 0x08;
    offer[13] = 0x00;
    uint8_t *oip = offer + 14;
    oip[0] = 0x45;
    oip[9] = 17;
    uint8_t *oudp = oip + 20;
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
    d->magic[0] = 99;
    d->magic[1] = 130;
    d->magic[2] = 83;
    d->magic[3] = 99;
    uint8_t *oo = (uint8_t *)d + sizeof(*d);
    *oo++ = 53;
    *oo++ = 1;
    *oo++ = 2;
    *oo++ = 255;
    size_t olen = (size_t)(oo - offer);
    for (int i = 0; i < 30000; i++) {
        static uint8_t mut[1024];
        size_t mlen = olen;
        if (next_rand() & 1) mlen = (size_t)(next_rand() % (olen + 1));
        memcpy(mut, offer, mlen);
        int flips = (int)(next_rand() % 6);
        for (int f = 0; f < flips && mlen; f++)
            mut[next_rand() % mlen] ^= (uint8_t)(1 << (next_rand() % 8));
        int mt = 0;
        struct dhcp_result res;
        uint8_t pm[6];
        memset(&res, 0, sizeof(res));
        (void)dhcp_parse_reply(mut, mlen, 0xdeadbeef, &mt, &res, pm);
        total++;
    }

    /* 4. mutated Ethernet frames into the L2/L3 shim */
    for (int i = 0; i < 40000; i++) {
        size_t len = (size_t)(next_rand() % 1600);
        rand_fill(buf, len);
        size_t rlen = 0;
        (void)frame_handle_in(buf, len, ipout, sizeof(ipout), reply,
                              sizeof(reply), &rlen);
        total++;
    }

    /* 5. wrap-path bounds: random sizes vs capacities (ASan guards overflow) */
    for (int i = 0; i < 20000; i++) {
        size_t elen = (size_t)(next_rand() % 2000);
        size_t cap = (size_t)(next_rand() % 2100);
        rand_fill(buf, elen < sizeof(buf) ? elen : sizeof(buf));
        size_t got = rndis_wrap_packet(buf, elen, out, cap);
        if (cap >= elen + sizeof(struct rndis_data_hdr)) {
            if (got != elen + sizeof(struct rndis_data_hdr)) {
                printf("FAIL wrap contract elen=%zu cap=%zu\n", elen, cap);
                return 1;
            }
        } else if (got != 0) {
            printf("FAIL wrap must refuse elen=%zu cap=%zu\n", elen, cap);
            return 1;
        }
        total++;
    }

    /* 6. checksums on random buffers */
    for (int i = 0; i < 10000; i++) {
        size_t len = (size_t)(next_rand() % 1500);
        rand_fill(buf, len);
        (void)ip_checksum(buf, len);
        uint8_t a[4] = {10, 0, 0, 1}, b[4] = {10, 0, 0, 2};
        if (len >= 8) (void)udp_checksum_ipv4(a, b, buf, len);
        total++;
    }

    printf("FUZZ OK (%ld iterations, no sanitizer aborts)\n", total);
    return 0;
}
