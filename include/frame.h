#ifndef CABLED_HOTSPOT_FRAME_H
#define CABLED_HOTSPOT_FRAME_H

#include <stddef.h>
#include <stdint.h>

/* L2<->L3 shim. utun is IP-only; RNDIS carries Ethernet.
 * - Outbound: synth Ethernet header (dst=peer MAC, src=our MAC).
 * - Inbound: learn peer MAC from src, answer ARP for our IP locally. */
void frame_init(const uint8_t our_mac[6], const uint8_t our_ip[4]);
void frame_set_peer(const uint8_t mac[6], const uint8_t ip[4]);
void frame_get_peer(uint8_t mac[6], uint8_t ip[4]);
int frame_has_peer(void);

/* Build eth frame for an outbound IP packet. Returns eth len or 0. */
size_t frame_wrap_out(const uint8_t *ip, size_t ip_len,
                      uint8_t *eth_out, size_t cap);
/* Build an ARP request for gateway (for learning). Returns len or 0. */
size_t frame_build_arp_request(uint8_t *out, size_t cap);
/* Handle one inbound eth frame:
 *  returns 1 + fills ip_out if it carries an IP packet for utun,
 *  returns 0 if consumed (ARP etc.), -1 on error.
 *  If an ARP reply is needed, builds it into reply_out (*reply_len). */
int frame_handle_in(const uint8_t *eth, size_t eth_len,
                    uint8_t *ip_out, size_t ip_cap,
                    uint8_t *reply_out, size_t reply_cap, size_t *reply_len);

#endif
