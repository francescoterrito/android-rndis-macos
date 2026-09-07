#include "frame.h"
#include "net_util.h"
#include <string.h>

static uint8_t g_our_mac[6];
static uint8_t g_our_ip[4];
static uint8_t g_peer_mac[6];
static uint8_t g_peer_ip[4];
static int g_has_peer = 0;

void frame_init(const uint8_t our_mac[6], const uint8_t our_ip[4]) {
    memcpy(g_our_mac, our_mac, 6);
    memcpy(g_our_ip, our_ip, 4);
    g_has_peer = 0;
    memset(g_peer_mac, 0, 6);
    memset(g_peer_ip, 0, 4);
}

void frame_set_peer(const uint8_t mac[6], const uint8_t ip[4]) {
    if (mac) memcpy(g_peer_mac, mac, 6);
    if (ip) memcpy(g_peer_ip, ip, 4);
    g_has_peer = 1;
}

void frame_get_peer(uint8_t mac[6], uint8_t ip[4]) {
    if (mac) memcpy(mac, g_peer_mac, 6);
    if (ip) memcpy(ip, g_peer_ip, 4);
}

int frame_has_peer(void) { return g_has_peer; }

size_t frame_wrap_out(const uint8_t *ip, size_t ip_len,
                      uint8_t *eth_out, size_t cap) {
    if (cap < ip_len + 14) return 0;
    /* If peer unknown (pre-DHCP broadcast), caller passes DHCP frames that
     * already contain Ethernet headers; this path is for utun IP packets. */
    if (g_has_peer) {
        memcpy(eth_out, g_peer_mac, 6);
    } else {
        memset(eth_out, 0xff, 6);
    }
    memcpy(eth_out + 6, g_our_mac, 6);
    eth_out[12] = 0x08;
    eth_out[13] = 0x00;
    memcpy(eth_out + 14, ip, ip_len);
    return ip_len + 14;
}

size_t frame_build_arp_request(uint8_t *out, size_t cap) {
    if (cap < 14 + 28) return 0;
    memset(out, 0xff, 6);
    memcpy(out + 6, g_our_mac, 6);
    out[12] = 0x08;
    out[13] = 0x06;
    struct arp_pkt *a = (struct arp_pkt *)(out + 14);
    a->htype[0] = 0;
    a->htype[1] = 1;
    a->ptype[0] = 0x08;
    a->ptype[1] = 0x00;
    a->hlen = 6;
    a->plen = 4;
    a->oper[0] = 0;
    a->oper[1] = 1;
    memcpy(a->sha, g_our_mac, 6);
    memcpy(a->spa, g_our_ip, 4);
    memset(a->tha, 0, 6);
    memcpy(a->tpa, g_peer_ip, 4);
    return 42;
}

int frame_handle_in(const uint8_t *eth, size_t eth_len,
                    uint8_t *ip_out, size_t ip_cap,
                    uint8_t *reply_out, size_t reply_cap, size_t *reply_len) {
    if (reply_len) *reply_len = 0;
    if (eth_len < 14) return -1;
    /* Learn source MAC -> peer (handles Samsung MAC randomization). */
    memcpy(g_peer_mac, eth + 6, 6);
    g_has_peer = 1;

    uint16_t etype = ((uint16_t)eth[12] << 8) | eth[13];
    if (etype == 0x0806) { /* ARP */
        if (eth_len < 42) return -1;
        const struct arp_pkt *a = (const struct arp_pkt *)(eth + 14);
        /* Validate header before trusting anything: untrusted USB bytes. */
        if (a->htype[0] != 0 || a->htype[1] != 1) return 0;
        if (a->ptype[0] != 0x08 || a->ptype[1] != 0x00) return 0;
        if (a->hlen != 6 || a->plen != 4) return 0;
        uint16_t oper = ((uint16_t)a->oper[0] << 8) | a->oper[1];
        if (oper == 2) { /* reply: learn gateway IP if it targets us */
            if (memcmp(a->tpa, g_our_ip, 4) == 0) {
                memcpy(g_peer_ip, a->spa, 4);
            }
            return 0;
        }
        if (oper == 1) { /* request for our IP? answer locally */
            if (memcmp(a->tpa, g_our_ip, 4) != 0) return 0;
            if (reply_cap < 42) return 0;
            memcpy(reply_out, a->sha, 6);
            memcpy(reply_out + 6, g_our_mac, 6);
            reply_out[12] = 0x08;
            reply_out[13] = 0x06;
            struct arp_pkt *r = (struct arp_pkt *)(reply_out + 14);
            r->htype[0] = 0;
            r->htype[1] = 1;
            r->ptype[0] = 0x08;
            r->ptype[1] = 0x00;
            r->hlen = 6;
            r->plen = 4;
            r->oper[0] = 0;
            r->oper[1] = 2;
            memcpy(r->sha, g_our_mac, 6);
            memcpy(r->spa, g_our_ip, 4);
            memcpy(r->tha, a->sha, 6);
            memcpy(r->tpa, a->spa, 4);
            memcpy(g_peer_ip, a->spa, 4);
            if (reply_len) *reply_len = 42;
            return 0;
        }
        return 0;
    }
    if (etype == 0x0800) { /* IPv4 -> utun */
        size_t ip_len = eth_len - 14;
        if (ip_len > ip_cap) return -1;
        /* Learn gateway IP from source address on first packets. */
        if (g_peer_ip[0] == 0 && ip_len >= 20) {
            /* Don't overwrite a DHCP-provided gateway with our own addr. */
            if (memcmp(eth + 14 + 12, g_our_ip, 4) != 0) {
                memcpy(g_peer_ip, eth + 14 + 12, 4);
            }
        }
        memcpy(ip_out, eth + 14, ip_len);
        return 1;
    }
    return 0; /* ignore non-IP */
}
