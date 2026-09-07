#include "route.h"
#include "log.h"
#include "net_util.h"
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Session-owned keys disappear even after a crash. Never overwrite the
 * global DNS dictionary, which belongs to configd and other services. */
static SCDynamicStoreRef store;
static int routes[2];
static char route_if[16];
static const char *nets[] = {"0.0.0.0/1", "128.0.0.0/1"};

static CFMutableDictionaryRef dictionary(void) {
    return CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
                                      &kCFTypeDictionaryValueCallBacks);
}
static void string_value(CFMutableDictionaryRef d, CFStringRef key, const char *s) {
    CFStringRef v = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
    CFDictionarySetValue(d, key, v);
    CFRelease(v);
}
static void array_value(CFMutableDictionaryRef d, CFStringRef key,
                         const char *a, const char *b) {
    CFMutableArrayRef array = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFStringRef v = CFStringCreateWithCString(NULL, a, kCFStringEncodingUTF8);
    CFArrayAppendValue(array, v); CFRelease(v);
    if (b) {
        v = CFStringCreateWithCString(NULL, b, kCFStringEncodingUTF8);
        CFArrayAppendValue(array, v); CFRelease(v);
    }
    CFDictionarySetValue(d, key, array); CFRelease(array);
}
static int publish(CFStringRef entity, CFDictionaryRef value) {
    CFStringRef key = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL,
        kSCDynamicStoreDomainState, CFSTR("android-rndis-macos"), entity);
    Boolean ok = SCDynamicStoreSetValue(store, key, value);
    CFRelease(key);
    return ok ? 0 : -1;
}
static int route_command(const char *verb, int i) {
    char cmd[256];
    /* ifname is validated below and comes from the kernel. Interface
     * routes vanish when utun closes, including after an unclean exit. */
    snprintf(cmd, sizeof(cmd), "/sbin/route -n %s -net %s -interface %s",
             verb, nets[i], route_if);
    return system(cmd);
}
int route_setup(const char *ifname, const uint8_t ip[4], const uint8_t mask[4],
                const uint8_t gw[4], const uint8_t dns[4], const uint8_t *dns2,
                int do_route, int do_dns) {
    if (store || routes[0] || routes[1]) return -1;
    if (strncmp(ifname, "utun", 4) || !ifname[4] ||
        strlen(ifname) >= sizeof(route_if) ||
        strspn(ifname + 4, "0123456789") != strlen(ifname + 4)) return -1;
    snprintf(route_if, sizeof(route_if), "%s", ifname);
    if (!do_route && !do_dns) return 0;
    if (do_route) {
        for (int i = 0; i < 2; i++) {
            if (route_command("add", i) != 0) {
                LOGE("cannot add %s (possibly a conflicting VPN route)", nets[i]);
                goto fail;
            }
            routes[i] = 1;
        }
    }
    CFMutableDictionaryRef options = dictionary();
    CFDictionarySetValue(options, kSCDynamicStoreUseSessionKeys, kCFBooleanTrue);
    store = SCDynamicStoreCreateWithOptions(NULL, CFSTR("AndroidRNDIS"), options, NULL, NULL);
    CFRelease(options);
    if (!store) goto fail;
    if (route_update(ifname, ip, mask, gw, dns, dns2, do_route, do_dns) != 0) goto fail;
    return 0;
fail:
    LOGE("network setup failed; rolling back this session");
    route_restore();
    return -1;
}
int route_update(const char *ifname, const uint8_t ip[4], const uint8_t mask[4],
                 const uint8_t gw[4], const uint8_t dns[4], const uint8_t *dns2,
                 int do_route, int do_dns) {
    if (!do_route && !do_dns) return 0;
    if (!store || strcmp(ifname, route_if)) return -1;
    char ips[16], masks[16], gws[16], dns1s[16], dns2s[16];
    ip_to_str(ip, ips); ip_to_str(mask, masks); ip_to_str(gw, gws);
    ip_to_str(dns, dns1s); if (dns2) ip_to_str(dns2, dns2s);
    CFMutableDictionaryRef d = dictionary();
    array_value(d, kSCPropNetIPv4Addresses, ips, NULL);
    array_value(d, kSCPropNetIPv4SubnetMasks, masks, NULL);
    string_value(d, kSCPropInterfaceName, ifname);
    /* Respect --no-route: do not ask configd to install a default router. */
    if (do_route) string_value(d, kSCPropNetIPv4Router, gws);
    int rc = publish(kSCEntNetIPv4, d); CFRelease(d);
    if (rc) return -1;
    d = dictionary();
    string_value(d, kSCPropNetInterfaceDeviceName, ifname);
    string_value(d, kSCPropNetInterfaceType, "utun");
    rc = publish(kSCEntNetInterface, d); CFRelease(d);
    if (rc) return -1;
    if (do_dns) {
        d = dictionary();
        array_value(d, kSCPropNetDNSServerAddresses, dns1s, dns2 ? dns2s : NULL);
        array_value(d, kSCPropNetDNSSupplementalMatchDomains, "", NULL);
        int order = 1;
        CFNumberRef n = CFNumberCreate(NULL, kCFNumberIntType, &order);
        CFDictionarySetValue(d, kSCPropNetDNSSearchOrder, n); CFRelease(n);
        rc = publish(kSCEntNetDNS, d); CFRelease(d);
        if (rc) return -1;
    }
    return 0;
}

void route_restore(void) {
    if (store) { CFRelease(store); store = NULL; }
    for (int i = 0; i < 2; i++) {
        if (routes[i]) { (void)route_command("delete", i); routes[i] = 0; }
    }
}
