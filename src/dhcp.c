#include "dhcp.h"
#include "net_util.h"
#include "usb.h"
#include "rndis_proto.h"
#include "frame.h"
#include "log.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static void build_ip_udp(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                         uint16_t sport, uint16_t dport,
                         const uint8_t *payload, size_t plen,
                         uint8_t *out, size_t *out_len) {
    struct ip_hdr *ip = (struct ip_hdr *)out;
    struct udp_hdr *udp = (struct udp_hdr *)(out + 20);
    ip->ver_ihl = 0x45;
    ip->tos = 0;
    put_be16(ip->tot_len, (uint16_t)(20 + 8 + plen));
    put_be16(ip->id, (uint16_t)(rand() & 0xffff));
    put_be16(ip->flags_frag, 0x4000); /* DF */
    ip->ttl = 64;
    ip->proto = 17;
    put_be16(ip->csum, 0);
    memcpy(ip->src, src_ip, 4);
    memcpy(ip->dst, dst_ip, 4);
    put_be16(ip->csum, ip_checksum(ip, 20));

    put_be16(udp->sport, sport);
    put_be16(udp->dport, dport);
    put_be16(udp->len, (uint16_t)(8 + plen));
    put_be16(udp->csum, 0);
    memcpy(out + 28, payload, plen);
    uint16_t c = udp_checksum_ipv4(src_ip, dst_ip, (uint8_t *)udp, 8 + plen);
    put_be16(udp->csum, c);
    *out_len = 20 + 8 + plen;
}

static size_t dhcp_payload(uint8_t *out, uint8_t msg, uint32_t xid,
                           const uint8_t req_ip[4], const uint8_t srv_ip[4],
                           const uint8_t mac[6]) {
    struct dhcp_fixed *d = (struct dhcp_fixed *)out;
    memset(d, 0, sizeof(*d));
    d->op = 1;
    d->htype = 1;
    d->hlen = 6;
    d->xid[0] = (xid >> 24) & 0xff;
    d->xid[1] = (xid >> 16) & 0xff;
    d->xid[2] = (xid >> 8) & 0xff;
    d->xid[3] = xid & 0xff;
    d->flags[0] = 0x80; /* broadcast */
    memcpy(d->chaddr, mac, 6);
    d->magic[0] = 99;
    d->magic[1] = 130;
    d->magic[2] = 83;
    d->magic[3] = 99;
    uint8_t *o = out + sizeof(*d);
    *o++ = 53;
    *o++ = 1;
    *o++ = msg;
    *o++ = 61;
    *o++ = 7;
    *o++ = 1;
    memcpy(o, mac, 6);
    o += 6;
    if (msg == 3 && req_ip && srv_ip) {
        *o++ = 50;
        *o++ = 4;
        memcpy(o, req_ip, 4);
        o += 4;
        *o++ = 54;
        *o++ = 4;
        memcpy(o, srv_ip, 4);
        o += 4;
    }
    *o++ = 55;
    *o++ = 6;
    *o++ = 1;
    *o++ = 3;
    *o++ = 6;
    *o++ = 51;
    *o++ = 58;
    *o++ = 59;
    *o++ = 255;
    /* RFC 2131: clients must support the 300-byte BOOTP minimum. */
    while (o - out < 300) *o++ = 0;
    return (size_t)(o - out);
}

static size_t dhcp_eth_frame(const uint8_t mac[6], uint8_t msg, uint32_t xid,
                             const uint8_t req_ip[4], const uint8_t srv_ip[4],
                             uint8_t *out, size_t cap) {
    uint8_t payload[576];
    size_t plen = dhcp_payload(payload, msg, xid, req_ip, srv_ip, mac);
    uint8_t ippkt[1500];
    size_t iplen = 0;
    const uint8_t zero[4] = {0, 0, 0, 0};
    const uint8_t bcast[4] = {255, 255, 255, 255};
    build_ip_udp(zero, bcast, 68, 67, payload, plen, ippkt, &iplen);
    if (cap < 14 + iplen) return 0;
    memset(out, 0xff, 6);
    memcpy(out + 6, mac, 6);
    out[12] = 0x08;
    out[13] = 0x00;
    memcpy(out + 14, ippkt, iplen);
    return 14 + iplen;
}

size_t dhcp_build_discover(const uint8_t mac[6], uint32_t xid,
                           uint8_t *out, size_t cap) {
    return dhcp_eth_frame(mac, 1, xid, NULL, NULL, out, cap);
}

size_t dhcp_build_request(const uint8_t mac[6], uint32_t xid,
                          const uint8_t req_ip[4], const uint8_t srv_ip[4],
                          uint8_t *out, size_t cap) {
    return dhcp_eth_frame(mac, 3, xid, req_ip, srv_ip, out, cap);
}

int dhcp_parse_reply(const uint8_t *eth, size_t len, uint32_t xid,
                     int *msg_type_out, struct dhcp_result *res,
                     uint8_t peer_mac[6]) {
    if (len < 14 + 20 + 8 + sizeof(struct dhcp_fixed)) return -1;
    if (eth[12] != 0x08 || eth[13] != 0x00) return -1;
    const uint8_t *ip = eth + 14;
    if ((ip[0] >> 4) != 4 || ip[9] != 17) return -1;
    size_t ihl = (ip[0] & 0x0f) * 4;
    size_t iplen = get_be16(ip + 2);
    if (ihl < 20 || iplen > len - 14 ||
        iplen < ihl + 8 + sizeof(struct dhcp_fixed) ||
        (get_be16(ip + 6) & 0x3fff)) return -1;
    const uint8_t *udp = ip + ihl;
    if (get_be16(udp) != 67 || get_be16(udp + 2) != 68) return -1;
    size_t udplen = get_be16(udp + 4);
    if (udplen < 8 + sizeof(struct dhcp_fixed) || udplen > iplen - ihl) return -1;
    const struct dhcp_fixed *d = (const struct dhcp_fixed *)(udp + 8);
    if (d->op != 2 || d->htype != 1 || d->hlen != 6) return -1;
    uint32_t rx = ((uint32_t)d->xid[0] << 24) | ((uint32_t)d->xid[1] << 16) |
                  ((uint32_t)d->xid[2] << 8) | d->xid[3];
    if (rx != xid) return -1;
    if (!(d->magic[0] == 99 && d->magic[1] == 130 && d->magic[2] == 83 &&
          d->magic[3] == 99))
        return -1;

    const uint8_t *o = (const uint8_t *)d + sizeof(*d);
    const uint8_t *end = udp + udplen;
    int msg = -1;
    const uint8_t *opt_mask = NULL, *opt_gw = NULL, *opt_dns = NULL,
                  *opt_dns2 = NULL, *opt_srv = NULL;
    uint32_t lease = 0, t1 = 0, t2 = 0;
    unsigned options = 0;
    while (o < end) {
        uint8_t code = *o++;
        if (code == 0) continue;
        if (code == 255) break;
        if (o >= end) return -1;
        uint8_t l = *o++;
        if ((size_t)(end - o) < l) return -1;
        if (code == 53 && l == 1) msg = o[0];
        if (code == 1 && l == 4) opt_mask = o;
        if (code == 3 && l >= 4) opt_gw = o;
        if (code == 6 && l >= 4) opt_dns = o;
        if (code == 6 && l >= 8) opt_dns2 = o + 4;
        if (code == 54 && l == 4) opt_srv = o;
        if (code == 51 || code == 58 || code == 59) {
            if (l != 4) return -1;
            uint32_t v = ((uint32_t)o[0] << 24) | ((uint32_t)o[1] << 16) |
                         ((uint32_t)o[2] << 8) | o[3];
            if (code == 51) { lease = v; options |= DHCP_OPT_LEASE; }
            if (code == 58) { t1 = v; options |= DHCP_OPT_T1; }
            if (code == 59) { t2 = v; options |= DHCP_OPT_T2; }
        }
        o += l;
    }
    if (msg != 2 && msg != 5 && msg != 6) return -1;
    if (!opt_srv || opt_srv[0] == 0 || opt_srv[0] >= 224) return -1;
    if (msg != 6 && (d->yiaddr[0] == 0 || d->yiaddr[0] >= 224)) return -1;
    if (eth[6] & 1) return -1;
    if (peer_mac) memcpy(peer_mac, eth + 6, 6);
    if (msg_type_out) *msg_type_out = msg;
    if (res) {
        memset(res, 0, sizeof(*res));
        memcpy(res->server, opt_srv, 4);
        memcpy(res->client_mac, d->chaddr, 6);
        memcpy(res->ip, d->yiaddr, 4);
        if (opt_mask)
            memcpy(res->mask, opt_mask, 4);
        else
            memcpy(res->mask, "\xff\xff\xff\x00", 4);
        if (opt_gw)
            memcpy(res->gw, opt_gw, 4);
        else if (opt_srv)
            memcpy(res->gw, opt_srv, 4);
        else
            memcpy(res->gw, "\xc0\xa8\x2a\x81", 4); /* 192.168.42.129 */
        if (opt_dns)
            memcpy(res->dns, opt_dns, 4);
        else
            memcpy(res->dns, res->gw, 4); /* no DNS option: use gateway */
        if (opt_dns2 && memcmp(opt_dns2, res->dns, 4) != 0) {
            memcpy(res->dns2, opt_dns2, 4);
            res->have_dns2 = 1;
        } else {
            res->have_dns2 = 0;
        }
        res->lease_sec = lease;
        res->renew_sec = t1; res->rebind_sec = t2;
        res->options = options | (opt_mask ? DHCP_OPT_MASK : 0) |
                       (opt_gw ? DHCP_OPT_ROUTER : 0) | (opt_dns ? DHCP_OPT_DNS : 0);
    }
    return 0;
}

/* Shared validated RNDIS parser, including hostile offset checks. */
struct exchange {
    uint32_t xid;
    const uint8_t *mac;
    int stage; /* 0 discover, 1 request, 2 bound, -1 NAK */
    int changed;
    struct dhcp_result net;
    uint8_t peer[6];
};
static void receive_reply(const uint8_t *eth, size_t len, void *ctx) {
    struct exchange *e = ctx;
    struct dhcp_result net;
    uint8_t peer[6];
    int mt;
    if (dhcp_parse_reply(eth, len, e->xid, &mt, &net, peer) != 0 ||
        memcmp(net.client_mac, e->mac, 6) != 0) return;
    if (e->stage == 0 && mt == 2) {
        e->net = net;
        e->stage = 1;
        e->changed = 1;
    } else if (e->stage == 1 && !memcmp(net.server, e->net.server, 4)) {
        if (mt == 6) { e->stage = -1; return; }
        if (mt != 5 || memcmp(net.ip, e->net.ip, 4)) return;
        /* Options omitted from an ACK retain the OFFER values. */
        if (!(net.options & DHCP_OPT_LEASE)) net.lease_sec = e->net.lease_sec;
        if (!(net.options & DHCP_OPT_MASK)) memcpy(net.mask, e->net.mask, 4);
        if (!(net.options & DHCP_OPT_ROUTER)) memcpy(net.gw, e->net.gw, 4);
        if (!(net.options & DHCP_OPT_DNS)) {
            memcpy(net.dns, e->net.dns, 4); memcpy(net.dns2, e->net.dns2, 4);
            net.have_dns2 = e->net.have_dns2;
        }
        if (!net.lease_sec) return;
        net.obtained_at = e->net.obtained_at;
        e->net = net;
        memcpy(e->peer, peer, 6);
        e->stage = 2;
    }
}
int dhcp_run(struct rndis_usb_dev *dev, const uint8_t our_mac[6],
             struct dhcp_result *res, uint8_t peer_mac[6], int timeout_sec,
             dhcp_cancel_cb cancelled, void *cancel_ctx) {
    uint8_t eth[1600], rx[16384], wire[2048];
    struct exchange e = {.xid = arc4random(), .mac = our_mac};
    double deadline = net_now() + timeout_sec, next_send = 0;
    while (net_now() < deadline) {
        if (cancelled && cancelled(cancel_ctx)) return -1;
        if (net_now() >= next_send || e.changed) {
            if (e.stage == 1 && e.changed) e.net.obtained_at = net_now();
            size_t n = e.stage == 0 ?
                dhcp_build_discover(our_mac, e.xid, eth, sizeof(eth)) :
                dhcp_build_request(our_mac, e.xid, e.net.ip, e.net.server,
                                   eth, sizeof(eth));
            size_t wn = rndis_wrap_packet(eth, n, wire, sizeof(wire));
            if (!n || !wn || usb_bulk_out(dev, wire, wn, 500) != 0) return -1;
            e.changed = 0;
            next_send = net_now() + 2;
        }
        size_t got = 0;
        if (usb_bulk_in(dev, rx, sizeof(rx), &got, 250) != 0) return -1;
        if (got) rndis_unwrap_packets(rx, got, receive_reply, &e);
        if (e.stage == -1) { LOGE("DHCP server rejected the lease"); return -1; }
        if (e.stage == 2) {
            *res = e.net;
            if (peer_mac) memcpy(peer_mac, e.peer, 6);
            return 0;
        }
    }
    LOGE("DHCP timeout");
    return -1;
}

static void lease_deadlines(struct dhcp_client *c) {
    if (c->net.lease_sec == UINT32_MAX) {
        c->renew_at = c->rebind_at = c->expires_at = 1e100;
        return;
    }
    double lease = c->net.lease_sec;
    double t1 = c->net.renew_sec, t2 = c->net.rebind_sec;
    if (!(t1 > 0 && t1 < lease)) t1 = lease * 0.5;
    if (!(t2 > t1 && t2 < lease)) t2 = lease * 0.875;
    if (t1 >= t2) { t1 = lease * 0.5; t2 = lease * 0.875; }
    c->renew_at = c->net.obtained_at + t1;
    c->rebind_at = c->net.obtained_at + t2;
    c->expires_at = c->net.obtained_at + lease;
}
int dhcp_client_start(struct dhcp_client *c, const struct dhcp_result *net,
                      uint32_t xid_seed) {
    if (!net->lease_sec) return -1;
    memset(c, 0, sizeof(*c));
    c->net = *net; c->xid = xid_seed; c->phase = DHCP_BOUND;
    lease_deadlines(c);
    return 0;
}
void dhcp_client_renew_now(struct dhcp_client *c, double now) {
    if (c->phase == DHCP_BOUND && now < c->expires_at) c->renew_at = now;
}
int dhcp_client_tick(struct dhcp_client *c, double now, const uint8_t peer[6],
                     uint8_t *out, size_t cap) {
    if (c->phase == DHCP_EXPIRED || now >= c->expires_at) {
        c->phase = DHCP_EXPIRED; return -1;
    }
    if (c->phase == DHCP_BOUND && now >= c->renew_at) {
        c->phase = DHCP_RENEWING;
        if (++c->xid == 0) ++c->xid;
        c->next_request = now;
        c->request_started = now;
    }
    if (c->phase == DHCP_RENEWING && now >= c->rebind_at) {
        c->phase = DHCP_REBINDING;
        c->next_request = now;
    }
    if (c->phase == DHCP_BOUND || now < c->next_request) return 0;
    /* RENEW/REBIND: ciaddr and source IP set, no options 50 or 54. */
    uint8_t payload[576];
    size_t plen = dhcp_payload(payload, 3, c->xid, NULL, NULL, c->net.client_mac);
    struct dhcp_fixed *d = (struct dhcp_fixed *)payload;
    memcpy(d->ciaddr, c->net.ip, 4);
    d->flags[0] = 0; /* We can receive unicast replies on our assigned address. */
    double elapsed = now - c->request_started;
    put_be16(d->secs, elapsed > 65535 ? 65535 : (uint16_t)elapsed);
    if (cap < 14 + 28 + plen) return 0;
    const uint8_t broadcast[6] = {255,255,255,255,255,255};
    int rebind = c->phase == DHCP_REBINDING;
    memcpy(out, rebind ? broadcast : peer, 6);
    memcpy(out + 6, c->net.client_mac, 6);
    out[12] = 8; out[13] = 0;
    size_t iplen;
    build_ip_udp(c->net.ip, rebind ? broadcast : c->net.server, 68, 67,
                 payload, plen, out + 14, &iplen);
    double boundary = rebind ? c->expires_at : c->rebind_at;
    double retry = (boundary - now) / 2;
    if (retry < 60) retry = 60;
    c->next_request = now + retry;
    return (int)(14 + iplen);
}
int dhcp_client_receive(struct dhcp_client *c, const uint8_t *eth, size_t len,
                        double now) {
    if (c->phase != DHCP_RENEWING && c->phase != DHCP_REBINDING) return 0;
    int msg;
    struct dhcp_result next;
    if (dhcp_parse_reply(eth, len, c->xid, &msg, &next, NULL) != 0 ||
        memcmp(next.client_mac, c->net.client_mac, 6)) return 0;
    if (c->phase == DHCP_RENEWING && memcmp(next.server, c->net.server, 4)) return 0;
    if (now >= c->expires_at || msg == 6) { c->phase = DHCP_EXPIRED; return -1; }
    if (msg != 5) return 1;
    if (memcmp(next.ip, c->net.ip, 4)) { c->phase = DHCP_EXPIRED; return -1; }
    if (!(next.options & DHCP_OPT_LEASE) || !next.lease_sec) return 1;
    /* Preserve omitted configuration, but derive new T1/T2 from the new lease. */
    if (!(next.options & DHCP_OPT_MASK)) memcpy(next.mask, c->net.mask, 4);
    if (!(next.options & DHCP_OPT_ROUTER)) memcpy(next.gw, c->net.gw, 4);
    if (!(next.options & DHCP_OPT_DNS)) {
        memcpy(next.dns, c->net.dns, 4); memcpy(next.dns2, c->net.dns2, 4);
        next.have_dns2 = c->net.have_dns2;
    }
    next.obtained_at = c->request_started;
    /* A response delayed beyond the newly granted lease cannot extend it. */
    if (next.lease_sec != UINT32_MAX && now >= next.obtained_at + next.lease_sec)
        return 1;
    c->net = next;
    c->phase = DHCP_BOUND;
    c->renewals++;
    lease_deadlines(c);
    return 2;
}
