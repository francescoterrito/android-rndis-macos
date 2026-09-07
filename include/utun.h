#ifndef CABLED_HOTSPOT_UTUN_H
#define CABLED_HOTSPOT_UTUN_H

#include <stddef.h>
#include <stdint.h>

/* macOS utun via PF_SYSTEM / SYSPROTO_CONTROL. utun is L3 (IP-only),
 * while RNDIS carries L2 Ethernet -> see frame.h for the shim.
 * Packets on the fd carry a 4-byte AF header (network order). */
int utun_create(char name_out[16]);
/* Configure point-to-point: ifconfig <if> inet <ip> <peer> netmask <mask> up */
int utun_ifconfig(const char *ifname, const char *ip, const char *peer,
                  const char *mask);
int utun_set_mtu(const char *ifname, int mtu);
/* Returns payload len (>0), 0 on would-block, -1 on error. */
int utun_read_ip(int fd, uint8_t *buf, size_t cap);
int utun_write_ip(int fd, const uint8_t *ip, size_t len);
int utun_close(int fd);

#endif
