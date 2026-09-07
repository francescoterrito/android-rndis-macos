/* macOS utun bring-up. Linux has no equivalent: usbnet gives a net_device
 * with DHCP done by NetworkManager; here we create the interface ourselves.
 */
#include "utun.h"
#include "log.h"
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <net/if_utun.h>

int utun_create(char name_out[16]) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; /* kernel picks utunN */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    char name[16] = {0};
    socklen_t nlen = sizeof(name);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &nlen) == 0) {
        if (name_out) strncpy(name_out, name, 15);
        LOGV("utun %s", name);
    } else if (name_out) {
        name_out[0] = '\0';
    }
    /* Deep socket buffers: absorb bursts so TCP never stalls on us. */
    int bufsize = 4 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    /* Non-blocking: the TX thread polls, the RX callback must never sleep. */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

int utun_ifconfig(const char *ifname, const char *ip, const char *peer,
                  const char *mask) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s inet %s %s netmask %s up",
             ifname, ip, peer, mask);
    LOGI("ifconfig %s %s peer %s", ifname, ip, peer);
    return system(cmd);
}

int utun_set_mtu(const char *ifname, int mtu) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s mtu %d", ifname, mtu);
    return system(cmd);
}

int utun_read_ip(int fd, uint8_t *buf, size_t cap) {
    uint8_t tmp[65540];
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n < 4) return -1;
    uint32_t af;
    memcpy(&af, tmp, 4);
    af = ntohl(af);
    if (af != AF_INET) return 0; /* ignore v6 for now */
    size_t len = (size_t)n - 4;
    if (len > cap) return -1;
    memcpy(buf, tmp + 4, len);
    return (int)len;
}

int utun_write_ip(int fd, const uint8_t *ip, size_t len) {
    uint8_t tmp[65540];
    if (len + 4 > sizeof(tmp)) return -1;
    uint32_t af = htonl(AF_INET);
    memcpy(tmp, &af, 4);
    memcpy(tmp + 4, ip, len);
    ssize_t n = write(fd, tmp, len + 4);
    return n == (ssize_t)(len + 4) ? 0 : -1;
}

int utun_close(int fd) { return close(fd); }
