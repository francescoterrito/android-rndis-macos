#ifndef CABLED_HOTSPOT_DHCP_H
#define CABLED_HOTSPOT_DHCP_H

#include <stdint.h>
#include <stddef.h>

struct dhcp_result {
    uint8_t ip[4];
    uint8_t mask[4];
    uint8_t gw[4];
    uint8_t dns[4];
    uint8_t dns2[4];
    uint8_t server[4];
    uint8_t client_mac[6];
    int have_dns2;
    uint32_t lease_sec, renew_sec, rebind_sec;
    unsigned options;
    double obtained_at; /* continuous clock at the first REQUEST */
};

enum {
    DHCP_OPT_MASK = 1, DHCP_OPT_ROUTER = 2, DHCP_OPT_DNS = 4,
    DHCP_OPT_LEASE = 8, DHCP_OPT_T1 = 16, DHCP_OPT_T2 = 32
};
enum dhcp_phase { DHCP_BOUND, DHCP_RENEWING, DHCP_REBINDING, DHCP_EXPIRED };
/* All client calls must be serialized by the caller. Explicit clock values
 * allow deterministic tests of hours-long leases, retries and sleep/wake. */
struct dhcp_client {
    struct dhcp_result net;
    enum dhcp_phase phase;
    uint32_t xid;
    double renew_at, rebind_at, expires_at, next_request, request_started;
    unsigned renewals;
};
int dhcp_client_start(struct dhcp_client *c, const struct dhcp_result *net,
                      uint32_t xid_seed);
/* Positive = Ethernet request length, 0 = no work, -1 = expired. */
int dhcp_client_tick(struct dhcp_client *c, double now, const uint8_t peer[6],
                     uint8_t *out, size_t cap);
/* 0 unrelated, 1 consumed, 2 renewed, -1 NAK/invalidated. */
int dhcp_client_receive(struct dhcp_client *c, const uint8_t *eth, size_t len,
                        double now);
/* Request an early renewal (e.g. after wake or a diagnostic signal). */
void dhcp_client_renew_now(struct dhcp_client *c, double now);

/* Build a DHCPDISCOVER/DHCPREQUEST packet (full eth frame). */
size_t dhcp_build_discover(const uint8_t mac[6], uint32_t xid,
                           uint8_t *out, size_t cap);
size_t dhcp_build_request(const uint8_t mac[6], uint32_t xid,
                          const uint8_t req_ip[4], const uint8_t srv_ip[4],
                          uint8_t *out, size_t cap);
/* Parse DHCP OFFER/ACK eth frame. msg_type_out: 2=OFFER,5=ACK,6=NAK. Returns 0 ok. */
int dhcp_parse_reply(const uint8_t *eth, size_t len, uint32_t xid,
                     int *msg_type_out, struct dhcp_result *res,
                     uint8_t peer_mac[6]);

typedef int (*dhcp_cancel_cb)(void *ctx);
struct rndis_usb_dev;
/* Full exchange over RNDIS bulk EPs. Returns 0 with res + peer_mac filled,
 * -1 on timeout. peer_mac is the phone's actual Ethernet source address seen
 * on the OFFER/ACK (may differ from the queried permanent address on Samsung,
 * which randomizes it per connection). */
int dhcp_run(struct rndis_usb_dev *dev, const uint8_t our_mac[6],
             struct dhcp_result *res, uint8_t peer_mac[6], int timeout_sec,
             dhcp_cancel_cb cancelled, void *cancel_ctx);

#endif
