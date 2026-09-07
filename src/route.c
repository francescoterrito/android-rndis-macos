#include "route.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Proper macOS DNS: register a configd network service + override Global DNS
 * via scutil (what VPNs do). Editing /etc/resolv.conf is NOT enough — the
 * system resolver (browsers, curl) reads the SC store and ignores the file.
 * This was the "ping works, browsing doesn't" bug.
 *
 * DNS and route setup follows hknsglm/android-usb-tether-macos (MIT):
 * configd service keys State:/Network/Service/<id>/{IPv4,Interface,DNS},
 * empty SupplementalMatchDomains with SearchOrder 1, Global DNS override,
 * cache flush + mDNSResponder HUP, split-default routes, all removed on
 * exit. Differences here: no DNS backup file (restore = key removal),
 * optional second server parameter, do_route/do_dns gating in one call,
 * service id "cabled-hotspot".
 */
#define SERVICE_ID "cabled-hotspot"

static int g_have_route = 0;
static int g_have_dns = 0;
static int g_have_service = 0;

int route_setup(const char *ifname, const uint8_t ip[4], const uint8_t mask[4],
                const uint8_t gw[4], const uint8_t dns[4], const uint8_t *dns2,
                int do_route, int do_dns) {
    char ips[16], msk[16], gws[16], dnss[16], dns2s[16] = "";
    snprintf(ips, sizeof(ips), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    snprintf(msk, sizeof(msk), "%u.%u.%u.%u", mask[0], mask[1], mask[2], mask[3]);
    snprintf(gws, sizeof(gws), "%u.%u.%u.%u", gw[0], gw[1], gw[2], gw[3]);
    snprintf(dnss, sizeof(dnss), "%u.%u.%u.%u", dns[0], dns[1], dns[2], dns[3]);
    if (dns2)
        snprintf(dns2s, sizeof(dns2s), " %u.%u.%u.%u", dns2[0], dns2[1],
                 dns2[2], dns2[3]);

    if (do_route || do_dns) {
        /* Register network service so configd/resolver know about utun. */
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
                 "scutil <<'EOF' >/dev/null 2>&1\n"
                 "d.init\n"
                 "d.add Addresses * %s\n"
                 "d.add SubnetMasks * %s\n"
                 "d.add Router %s\n"
                 "d.add InterfaceName %s\n"
                 "set State:/Network/Service/%s/IPv4\n"
                 "quit\n"
                 "EOF",
                 ips, msk, gws, ifname, SERVICE_ID);
        (void)system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "scutil <<'EOF' >/dev/null 2>&1\n"
                 "d.init\n"
                 "d.add DeviceName %s\n"
                 "d.add Type utun\n"
                 "set State:/Network/Service/%s/Interface\n"
                 "quit\n"
                 "EOF",
                 ifname, SERVICE_ID);
        (void)system(cmd);
        g_have_service = 1;
        LOGI("registered network service '%s' on %s", SERVICE_ID, ifname);
    }

    if (do_dns) {
        char cmd[1024];
        /* Per-service DNS with empty supplemental match = used for all lookups. */
        snprintf(cmd, sizeof(cmd),
                 "scutil <<'EOF' >/dev/null 2>&1\n"
                 "d.init\n"
                 "d.add ServerAddresses * %s%s\n"
                 "d.add SupplementalMatchDomains * \"\"\n"
                 "d.add SearchOrder # 1\n"
                 "set State:/Network/Service/%s/DNS\n"
                 "quit\n"
                 "EOF",
                 dnss, dns2s, SERVICE_ID);
        (void)system(cmd);
        /* Global override so resolver #1 picks it up immediately. */
        snprintf(cmd, sizeof(cmd),
                 "scutil <<'EOF' >/dev/null 2>&1\n"
                 "d.init\n"
                 "d.add ServerAddresses * %s%s\n"
                 "set State:/Network/Global/DNS\n"
                 "quit\n"
                 "EOF",
                 dnss, dns2s);
        (void)system(cmd);
        (void)system("dscacheutil -flushcache 2>/dev/null");
        (void)system("killall -HUP mDNSResponder 2>/dev/null");
        g_have_dns = 1;
        LOGI("dns -> %s%s (scutil)", dnss, dns2s);
    }

    if (do_route) {
        /* Split-default (/1s) beats the original default without destroying it. */
        char cmd[160];
        snprintf(cmd, sizeof(cmd),
                 "/sbin/route add -net 0.0.0.0/1 %s >/dev/null 2>&1", gws);
        LOGI("route 0.0.0.0/1 -> %s", gws);
        (void)system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "/sbin/route add -net 128.0.0.0/1 %s >/dev/null 2>&1", gws);
        (void)system(cmd);
        g_have_route = 1;
    }
    return 0;
}

void route_restore(void) {
    if (g_have_route) {
        (void)system("/sbin/route delete -net 0.0.0.0/1 >/dev/null 2>&1");
        (void)system("/sbin/route delete -net 128.0.0.0/1 >/dev/null 2>&1");
        LOGI("routes restored");
        g_have_route = 0;
    }
    if (g_have_dns) {
        (void)system("scutil <<'EOF' >/dev/null 2>&1\n"
                     "remove State:/Network/Global/DNS\n"
                     "quit\n"
                     "EOF");
        g_have_dns = 0;
    }
    if (g_have_service) {
        (void)system("scutil <<'EOF' >/dev/null 2>&1\n"
                     "remove State:/Network/Service/" SERVICE_ID "/IPv4\n"
                     "remove State:/Network/Service/" SERVICE_ID "/DNS\n"
                     "remove State:/Network/Service/" SERVICE_ID "/Interface\n"
                     "quit\n"
                     "EOF");
        (void)system("dscacheutil -flushcache 2>/dev/null");
        (void)system("killall -HUP mDNSResponder 2>/dev/null");
        LOGI("network service unregistered, dns restored");
        g_have_service = 0;
    }
}
