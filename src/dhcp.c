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
    if (msg == 3) {
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
    *o++ = 4;
    *o++ = 1;
    *o++ = 3;
    *o++ = 6;
    *o++ = 51;
    *o++ = 255;
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
    if (len < 14 + ihl + 8 + sizeof(struct dhcp_fixed)) return -1;
    const uint8_t *udp = ip + ihl;
    if (get_be16(udp) != 67 || get_be16(udp + 2) != 68) return -1;
    const struct dhcp_fixed *d =
        (const struct dhcp_fixed *)(udp + 8);
    if (d->op != 2) return -1;
    uint32_t rx = ((uint32_t)d->xid[0] << 24) | ((uint32_t)d->xid[1] << 16) |
                  ((uint32_t)d->xid[2] << 8) | d->xid[3];
    if (rx != xid) return -1;
    if (!(d->magic[0] == 99 && d->magic[1] == 130 && d->magic[2] == 83 &&
          d->magic[3] == 99))
        return -1;
    if (peer_mac) memcpy(peer_mac, eth + 6, 6);

    const uint8_t *o = (const uint8_t *)d + sizeof(*d);
    const uint8_t *end = eth + len;
    int msg = -1;
    const uint8_t *opt_mask = NULL, *opt_gw = NULL, *opt_dns = NULL,
                  *opt_dns2 = NULL, *opt_srv = NULL;
    uint32_t lease = 0;
    while (o + 2 <= end) {
        uint8_t code = *o++;
        if (code == 0) continue;
        if (code == 255) break;
        if (o >= end) break;
        uint8_t l = *o++;
        if (o + l > end) break;
        if (code == 53 && l == 1) msg = o[0];
        if (code == 1 && l == 4) opt_mask = o;
        if (code == 3 && l >= 4) opt_gw = o;
        if (code == 6 && l >= 4) opt_dns = o;
        if (code == 6 && l >= 8) opt_dns2 = o + 4;
        if (code == 54 && l == 4) opt_srv = o;
        if (code == 51 && l == 4)
            lease = ((uint32_t)o[0] << 24) | ((uint32_t)o[1] << 16) |
                    ((uint32_t)o[2] << 8) | o[3];
        o += l;
    }
    if (msg != 2 && msg != 5) return -1;
    if (msg_type_out) *msg_type_out = msg;
    if (res) {
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
    }
    return 0;
}

int dhcp_run(struct rndis_usb_dev *dev, const uint8_t our_mac[6],
             struct dhcp_result *res, uint8_t peer_mac[6], int timeout_sec) {
    uint8_t eth[1600], rx[65536];
    /* XID must be stable across DISCOVER->REQUEST per RFC; use time+rand. */
    uint32_t xid = (uint32_t)time(NULL) ^ (uint32_t)rand();
    if (xid == 0) xid = 0x12345678;

    size_t dlen = dhcp_build_discover(our_mac, xid, eth, sizeof(eth));
    if (!dlen) return -1;
    uint8_t wbuf[2048];
    size_t wlen = rndis_wrap_packet(eth, dlen, wbuf, sizeof(wbuf));
    if (!wlen) return -1;

    time_t deadline = time(NULL) + timeout_sec;
    uint8_t srv_ip[4] = {0};
    uint8_t offered[4] = {0};
    int have_offer = 0;
    int tries = 0;

    /* Simple state machine: DISCOVER until OFFER, then REQUEST until ACK. */
    if (usb_bulk_out(dev, wbuf, wlen, 1000) != 0) {
        LOGE("DHCP: bulk-OUT discover failed");
        return -1;
    }
    LOGV("DHCP: DISCOVER xid=%08x", xid);

    while (time(NULL) < deadline) {
        size_t got = 0;
        int rc = usb_bulk_in(dev, rx, sizeof(rx), &got, 1000);
        if (rc != 0 || got == 0) {
            if (++tries % 4 == 0) {
                /* re-send current stage */
                const uint8_t *frame = eth;
                size_t flen = dlen;
                uint8_t req[1600];
                if (have_offer) {
                    flen = dhcp_build_request(our_mac, xid, offered, srv_ip,
                                              req, sizeof(req));
                    frame = req;
                    /* keep req frame for retransmits */
                    memcpy(eth, req, flen);
                    dlen = flen;
                }
                wlen = rndis_wrap_packet(frame, flen, wbuf, sizeof(wbuf));
                if (wlen) usb_bulk_out(dev, wbuf, wlen, 500);
            }
            continue;
        }
        /* rx may hold batched RNDIS packets; iterate each eth frame. */
        /* Inline unwrap to also handle partial batches across reads. */
        size_t off = 0;
        while (off + 44 <= got) {
            uint32_t mtype = ((uint32_t)rx[off]) | ((uint32_t)rx[off + 1] << 8) |
                             ((uint32_t)rx[off + 2] << 16) |
                             ((uint32_t)rx[off + 3] << 24);
            uint32_t mlen = ((uint32_t)rx[off + 4]) |
                            ((uint32_t)rx[off + 5] << 8) |
                            ((uint32_t)rx[off + 6] << 16) |
                            ((uint32_t)rx[off + 7] << 24);
            uint32_t doff = ((uint32_t)rx[off + 8]) |
                            ((uint32_t)rx[off + 9] << 8) |
                            ((uint32_t)rx[off + 10] << 16) |
                            ((uint32_t)rx[off + 11] << 24);
            uint32_t dlen2 = ((uint32_t)rx[off + 12]) |
                             ((uint32_t)rx[off + 13] << 8) |
                             ((uint32_t)rx[off + 14] << 16) |
                             ((uint32_t)rx[off + 15] << 24);
            if (mtype != 1 || mlen < 44 || off + mlen > got) break;
            const uint8_t *frm = rx + off + 8 + doff;
            size_t flen = dlen2;
            if (8 + doff + dlen2 <= mlen && flen >= 42) {
                int mt = -1;
                struct dhcp_result tmp;
                uint8_t pm[6];
                if (dhcp_parse_reply(frm, flen, xid, &mt, &tmp, pm) == 0) {
                    if (!have_offer && mt == 2) {
                        char s[16];
                        ip_to_str(tmp.ip, s);
                        LOGI("DHCP OFFER %s", s);
                        memcpy(offered, tmp.ip, 4);
                        /* server id may be in gw field already */
                        memcpy(srv_ip, tmp.gw, 4);
                        *res = tmp;
                        have_offer = 1;
                        dlen = dhcp_build_request(our_mac, xid, offered,
                                                  srv_ip, eth, sizeof(eth));
                        wlen = rndis_wrap_packet(eth, dlen, wbuf, sizeof(wbuf));
                        if (wlen) usb_bulk_out(dev, wbuf, wlen, 1000);
                        LOGV("DHCP: REQUEST %s", s);
                    } else if (have_offer && mt == 5) {
                        char s[16], g[16], n[16], p[18];
                        ip_to_str(tmp.ip, s);
                        ip_to_str(tmp.gw, g);
                        ip_to_str(tmp.dns, n);
                        mac_to_str(pm, p);
                        LOGI("DHCP ACK ip=%s gw=%s dns=%s peer=%s", s, g, n, p);
                        *res = tmp;
                        if (peer_mac) memcpy(peer_mac, pm, 6);
                        frame_set_peer(pm, tmp.gw);
                        return 0;
                    }
                }
            }
            if (mlen == 0) break;
            off += mlen;
        }
    }
    LOGE("DHCP timeout");
    return -1;
}
