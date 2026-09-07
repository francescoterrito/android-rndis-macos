#include "net_util.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

double net_now(void) {
#ifdef __APPLE__
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return (double)mach_continuous_time() * tb.numer / tb.denom / 1e9;
#else
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}

uint16_t ip_checksum(const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint16_t)p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t udp_checksum_ipv4(const uint8_t src[4], const uint8_t dst[4],
                           const uint8_t *udp, size_t udp_len) {
    uint32_t sum = 0;
    sum += ((uint16_t)src[0] << 8 | src[1]) + ((uint16_t)src[2] << 8 | src[3]);
    sum += ((uint16_t)dst[0] << 8 | dst[1]) + ((uint16_t)dst[2] << 8 | dst[3]);
    sum += 17 + (uint32_t)udp_len;
    const uint8_t *p = udp;
    size_t len = udp_len;
    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len) sum += (uint16_t)p[0] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t c = (uint16_t)~sum;
    return c == 0 ? 0xffff : c;
}

void mac_to_str(const uint8_t m[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

void ip_to_str(const uint8_t ip[4], char out[16]) {
    snprintf(out, 16, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

int ip_from_str(const char *s, uint8_t out[4]) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    out[0] = (uint8_t)a;
    out[1] = (uint8_t)b;
    out[2] = (uint8_t)c;
    out[3] = (uint8_t)d;
    return 0;
}
