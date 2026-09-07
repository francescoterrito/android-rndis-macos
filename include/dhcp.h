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
    int have_dns2;
    uint32_t lease_sec;
};

/* Build a DHCPDISCOVER/DHCPREQUEST packet (full eth frame). */
size_t dhcp_build_discover(const uint8_t mac[6], uint32_t xid,
                           uint8_t *out, size_t cap);
size_t dhcp_build_request(const uint8_t mac[6], uint32_t xid,
                          const uint8_t req_ip[4], const uint8_t srv_ip[4],
                          uint8_t *out, size_t cap);
/* Parse DHCP OFFER/ACK eth frame. msg_type_out: 2=OFFER,5=ACK. Returns 0 ok. */
int dhcp_parse_reply(const uint8_t *eth, size_t len, uint32_t xid,
                     int *msg_type_out, struct dhcp_result *res,
                     uint8_t peer_mac[6]);

struct rndis_usb_dev;
/* Full exchange over RNDIS bulk EPs. Returns 0 with res + peer_mac filled,
 * -1 on timeout. peer_mac is the phone's actual Ethernet source address seen
 * on the OFFER/ACK (may differ from the queried permanent address on Samsung,
 * which randomizes it per connection). */
int dhcp_run(struct rndis_usb_dev *dev, const uint8_t our_mac[6],
             struct dhcp_result *res, uint8_t peer_mac[6], int timeout_sec);

#endif
