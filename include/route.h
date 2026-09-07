#ifndef CABLED_HOTSPOT_ROUTE_H
#define CABLED_HOTSPOT_ROUTE_H

#include <stdint.h>

/* Session-owned SystemConfiguration DNS + interface split-default routes. */
int route_setup(const char *ifname, const uint8_t ip[4], const uint8_t mask[4],
                const uint8_t gw[4], const uint8_t dns[4], const uint8_t *dns2,
                int do_route, int do_dns);
/* Update an existing service without withdrawing its routes or DNS. */
int route_update(const char *ifname, const uint8_t ip[4], const uint8_t mask[4],
                 const uint8_t gw[4], const uint8_t dns[4], const uint8_t *dns2,
                 int do_route, int do_dns);
void route_restore(void);

#endif
