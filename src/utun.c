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
#include <sys/uio.h>
#include <errno.h>

int utun_create(char name_out[16]) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) { close(fd); return -1; }
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
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { close(fd); return -1; }
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
    uint32_t af;
    struct iovec iov[] = {{&af, sizeof(af)}, {buf, cap}};
    struct msghdr msg = {.msg_iov = iov, .msg_iovlen = 2};
    ssize_t n;
    do { n = recvmsg(fd, &msg, 0); } while (n < 0 && errno == EINTR);
    if (n < 0)
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    if (n < 4 || (msg.msg_flags & MSG_TRUNC)) return -1;
    if (ntohl(af) != AF_INET) return 0;
    return (int)(n - 4);
}
int utun_write_ip(int fd, const uint8_t *ip, size_t len) {
    if (len > 65535) return -1;
    uint32_t af = htonl(AF_INET);
    struct iovec iov[] = {{&af, sizeof(af)}, {(void *)ip, len}};
    ssize_t n;
    do { n = writev(fd, iov, 2); } while (n < 0 && errno == EINTR);
    return n == (ssize_t)(len + 4) ? 0 : -1;
}

int utun_close(int fd) { return close(fd); }
