#ifndef CABLED_HOTSPOT_NET_UTIL_H
#define CABLED_HOTSPOT_NET_UTIL_H

#include <stdint.h>
#include <stddef.h>

#pragma pack(push, 1)
struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint8_t type[2]; /* BE: 0x0800 IP, 0x0806 ARP */
};

struct arp_pkt {
    uint8_t htype[2];   /* 1 ethernet */
    uint8_t ptype[2];   /* 0x0800 */
    uint8_t hlen;       /* 6 */
    uint8_t plen;       /* 4 */
    uint8_t oper[2];    /* 1 req, 2 reply */
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
};

struct ip_hdr {
    uint8_t ver_ihl;    /* 0x45 */
    uint8_t tos;
    uint8_t tot_len[2]; /* BE */
    uint8_t id[2];
    uint8_t flags_frag[2];
    uint8_t ttl;
    uint8_t proto;      /* 17 UDP, 1 ICMP */
    uint8_t csum[2];
    uint8_t src[4];
    uint8_t dst[4];
};

struct udp_hdr {
    uint8_t sport[2];
    uint8_t dport[2];
    uint8_t len[2];
    uint8_t csum[2];
};

struct dhcp_fixed {
    uint8_t op, htype, hlen, hops;
    uint8_t xid[4];
    uint8_t secs[2], flags[2];
    uint8_t ciaddr[4], yiaddr[4], siaddr[4], giaddr[4];
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t magic[4]; /* 99,130,83,99 */
    /* options follow */
};
#pragma pack(pop)

uint16_t ip_checksum(const void *buf, size_t len);
uint16_t udp_checksum_ipv4(const uint8_t src[4], const uint8_t dst[4],
                           const uint8_t *udp, size_t udp_len);

static inline uint16_t be16(uint16_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (uint16_t)((v >> 8) | (v << 8));
#else
    return v;
#endif
}
static inline uint32_t be32(uint32_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(v);
#else
    return v;
#endif
}
static inline void put_be16(uint8_t *p, uint16_t v) {
    uint16_t b = be16(v);
    __builtin_memcpy(p, &b, 2);
}
static inline uint16_t get_be16(const uint8_t *p) {
    uint16_t b;
    __builtin_memcpy(&b, p, 2);
    return be16(b);
}

void mac_to_str(const uint8_t m[6], char out[18]);
void ip_to_str(const uint8_t ip[4], char out[16]);
int ip_from_str(const char *s, uint8_t out[4]);

#endif
