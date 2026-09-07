/* Opt-in hardware diagnostic: handshake + DHCP, no Mac routes/DNS/utun. */
#include "usb.h"
#include "dhcp.h"
#include "net_util.h"
#include <stdio.h>
#include <string.h>
int g_verbose = 1;
int main(void) {
    struct rndis_usb_dev *dev = NULL;
    uint8_t mac[6], peer[6];
    uint32_t limit;
    int rc = 1;
    if (usb_find_rndis(&dev, NULL)) return 1;
    if (usb_rndis_claim(dev) || rndis_bind_seq(dev, mac, &limit)) goto done;
    struct dhcp_result net;
    if (!dhcp_run(dev, mac, &net, peer, 15, NULL, NULL)) {
        char ip[16], gw[16], dns[16], server[16], pm[18];
        ip_to_str(net.ip, ip); ip_to_str(net.gw, gw);
        ip_to_str(net.dns, dns); ip_to_str(net.server, server); mac_to_str(peer, pm);
        printf("DHCP OK ip=%s gateway=%s dns=%s server=%s peer=%s lease=%u\n",
               ip, gw, dns, server, pm, net.lease_sec);
        rc = 0;
    }
    rndis_halt(dev);
done:
    usb_rndis_close(dev);
    return rc;
}
