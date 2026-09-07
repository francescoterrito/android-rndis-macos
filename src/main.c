/* Orchestration: usb -> rndis bind -> DHCP -> utun -> bridge.
 * Linux equivalent of usbnet_probe + dhcp client + net_device, in userspace.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <poll.h>

#include "usb.h"
#include "utun.h"
#include "rndis.h"
#include "rndis_proto.h"
#include "frame.h"
#include "dhcp.h"
#include "route.h"
#include "net_util.h"
#include "log.h"

int g_verbose = 0;

static atomic_int g_running = 1;
static int g_utun = -1;
static char g_ifname[16] = {0};

/* Cross-thread statistics: plain integers would be data races (UB in C11),
 * so all counters are atomic. Writers: event thread (rx), TX thread (tx).
 * Reader: supervision thread after/while running (loads are lock-free). */
static atomic_ullong g_rx_bytes = 0, g_tx_bytes = 0;
static atomic_ullong g_rx_pkts = 0, g_tx_pkts = 0;
static atomic_ullong g_tx_drops = 0, g_rx_drops = 0;

/* Async pipeline depths. 16 RX transfers keep the IN pipe permanently fed;
 * 32 TX slots absorb bursts from the stack. Buffers are 16KB; no USB
 * transfer may exceed the device's max_transfer_size (4740 on Samsung). */
#define RX_POOL_N 16
#define TX_POOL_N 32
#define XFER_BUF 16384
#define TX_BATCH_FRAMES 4

struct opts {
    int probe;
    int watch;
    int no_route;
    int no_dns;
    int verbose;
    uint8_t static_ip[4];
    uint8_t gateway[4];
    uint8_t netmask[4];
    uint8_t dns[4];
    int have_static;
    int have_gateway;
    int have_dns;
};

static void usage(void) {
    fprintf(stderr,
            "usage: cabled-hotspot [options]\n"
            "  --probe            list USB + RNDIS handshake only, no network changes\n"
            "  --watch            reconnect automatically when phone appears\n"
            "  --no-route         don't touch default route\n"
            "  --no-dns           don't touch DNS settings\n"
            "  --static IP        skip DHCP, use this IP\n"
            "  --gateway IP       gateway for --static (default 192.168.42.129)\n"
            "  --netmask IP       (default 255.255.255.0)\n"
            "  --dns IP           (default = gateway)\n"
            "  --verbose          debug logging\n");
}

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static void *keepalive_thread(void *arg) {
    struct rndis_usb_dev *dev = arg;
    while (g_running) {
        for (int i = 0; i < 50 && g_running; i++) usleep(100000);
        if (!g_running) break;
        if (rndis_keepalive(dev) == 0)
            LOGV("keepalive ok");
        else
            LOGV("keepalive failed");
    }
    return NULL;
}

struct rx_ctx {
    struct rndis_usb_dev *dev;
    struct usb_tx_pool *txpool; /* set before RX completions can arrive */
};

struct bridge_ctx {
    struct rndis_usb_dev *dev;
    struct usb_tx_pool *txpool;
    size_t max_transfer;
};

static void deliver_frame(const uint8_t *eth, size_t len, void *ctx) {
    struct rx_ctx *c = ctx;
    static uint8_t ipbuf[65536];
    static uint8_t reply[1600];
    size_t rlen = 0;
    int r = frame_handle_in(eth, len, ipbuf, sizeof(ipbuf), reply,
                            sizeof(reply), &rlen);
    if (rlen && c->dev && c->txpool) {
        /* Runs on the event thread: blocking USB calls are forbidden here
         * (libusb returns BUSY), so answer via the async TX pool. */
        size_t cap = 0;
        uint8_t *b = usb_tx_try_acquire(c->txpool, &cap);
        if (b) {
            size_t wl = rndis_wrap_packet(reply, rlen, b, cap);
            if (wl == 0 || usb_tx_submit(c->txpool, b, wl, 1000) != 0)
                usb_tx_release(c->txpool, b);
        }
    }
    if (r == 1) {
        size_t iplen = len - 14;
        if (g_utun >= 0 && utun_write_ip(g_utun, ipbuf, iplen) == 0) {
            atomic_fetch_add(&g_rx_bytes, (unsigned long long)iplen);
            atomic_fetch_add(&g_rx_pkts, 1ULL);
        } else {
            atomic_fetch_add(&g_rx_drops, 1ULL);
        }
    }
}

/* Runs on the USB event thread (serialized). */
static void on_usb_frame(uint8_t *buf, size_t len, void *ctx) {
    int n = rndis_unwrap_packets(buf, len, deliver_frame, ctx);
    if (n < 0) LOGV("rx framing error (%zu bytes)", len);
}

static void *event_thread(void *arg) {
    struct rndis_usb_dev *dev = arg;
    while (g_running) usb_handle_events(dev, 250);
    return NULL;
}

/* Read one IP packet from utun, wrap as Ethernet. 0 ok, -1 none/stop. */
static int read_one_eth(uint8_t *eth, size_t cap, size_t *ethlen, int wait_ms) {
    static uint8_t ipbuf[65536]; /* TX thread is the only caller */
    if (!g_running || g_utun < 0) return -1;
    struct pollfd pfd = {.fd = g_utun, .events = POLLIN};
    int r = poll(&pfd, 1, wait_ms);
    if (!g_running) return -1;
    if (r <= 0 || !(pfd.revents & POLLIN)) return -1;
    int len = utun_read_ip(g_utun, ipbuf, sizeof(ipbuf));
    if (len <= 0) return -1;
    size_t el = frame_wrap_out(ipbuf, (size_t)len, eth, cap);
    if (!el) return -1;
    *ethlen = el;
    return 0;
}

static void *tx_thread(void *arg) {
    struct bridge_ctx *b = arg;
    uint8_t eth[1600];
    size_t usable = b->max_transfer;
    if (usable < 2048) {
        LOGE("device max_transfer %zu absurdly small, clamping batch to 2048",
             usable);
        usable = 2048;
    }
    while (g_running) {
        size_t cap = 0;
        uint8_t *batch = usb_tx_acquire(b->txpool, &cap);
        if (!batch) break;
        if (cap < usable) usable = cap;
        size_t blen = 0, npack = 0, nbytes = 0, ethlen = 0;
        if (read_one_eth(eth, sizeof(eth), &ethlen, 100) != 0) {
            usb_tx_release(b->txpool, batch);
            continue;
        }
        for (;;) {
            size_t wlen =
                rndis_wrap_packet(eth, ethlen, batch + blen, usable - blen);
            if (wlen == 0) break; /* batch full (or frame too big) */
            blen += wlen;
            npack++;
            nbytes += ethlen - 14;
            if (npack >= TX_BATCH_FRAMES) break;
            if (read_one_eth(eth, sizeof(eth), &ethlen, 0) != 0) break;
        }
        if (blen == 0) {
            usb_tx_release(b->txpool, batch);
            atomic_fetch_add(&g_tx_drops, 1ULL);
            continue;
        }
        int rc = usb_tx_submit(b->txpool, batch, blen, 2000);
        if (rc == -2) {
            LOGE("device gone (TX)");
            g_running = 0;
            break;
        }
        if (rc == 0) {
            atomic_fetch_add(&g_tx_pkts, (unsigned long long)npack);
            atomic_fetch_add(&g_tx_bytes, (unsigned long long)nbytes);
        } else {
            LOGV("bulk-OUT submit failed");
            atomic_fetch_add(&g_tx_drops, 1ULL);
        }
    }
    return NULL;
}

static int run_once(struct opts *o) {
    struct rndis_usb_dev *dev = NULL;
    const struct usb_match *m = NULL;
    if (usb_find_rndis(&dev, &m) != 0) return -1;
    if (usb_rndis_claim(dev) != 0) {
        usb_rndis_close(dev);
        return -1;
    }

    uint8_t dev_mac[6] = {0};
    uint32_t max_transfer = 16384;
    if (rndis_bind_seq(dev, dev_mac, &max_transfer) != 0) {
        usb_rndis_close(dev);
        return -1;
    }
    char macs[18];
    mac_to_str(dev_mac, macs);
    LOGI("RNDIS bound mac=%s max_transfer=%u %s", macs, max_transfer,
         m ? m->desc : "");

    if (o->probe) {
        rndis_halt(dev);
        usb_rndis_close(dev);
        return 0;
    }

    /* Our MAC: locally-administered derivative (avoid colliding with phone,
     * which matters for Samsung MAC randomization + ARP learning). */
    uint8_t our_mac[6];
    memcpy(our_mac, dev_mac, 6);
    our_mac[0] |= 0x02;
    our_mac[5] ^= 0x01;

    struct dhcp_result net;
    memset(&net, 0, sizeof(net));
    uint8_t dhcp_peer[6] = {0};
    int have_dhcp_peer = 0;
    if (o->have_static) {
        memcpy(net.ip, o->static_ip, 4);
        memcpy(net.mask, o->netmask, 4);
        memcpy(net.gw, o->gateway, 4);
        memcpy(net.dns, o->have_dns ? o->dns : o->gateway, 4);
        LOGI("static ip in use (DHCP skipped)");
    } else {
        uint8_t zero[4] = {0, 0, 0, 0};
        frame_init(our_mac, zero);
        LOGI("DHCP discover...");
        if (dhcp_run(dev, our_mac, &net, dhcp_peer, 15) != 0) {
            LOGE("DHCP failed, fallback 192.168.42.100/24 gw 192.168.42.129");
            ip_from_str("192.168.42.100", net.ip);
            ip_from_str("255.255.255.0", net.mask);
            ip_from_str("192.168.42.129", net.gw);
            memcpy(net.dns, net.gw, 4);
        } else {
            have_dhcp_peer = 1;
        }
    }
    frame_init(our_mac, net.ip);
    if (have_dhcp_peer) {
        /* Samsung randomizes the on-wire MAC per connection: the queried
         * permanent address is NOT what the phone sends from. */
        char p[18], q[18];
        mac_to_str(dhcp_peer, p);
        mac_to_str(dev_mac, q);
        LOGI("peer %s (queried %s)", p, q);
        frame_set_peer(dhcp_peer, net.gw);
    } else {
        frame_set_peer(dev_mac, net.gw);
    }

    char ips[16], gws[16], msk[16], dns[16], dns2[16] = "";
    ip_to_str(net.ip, ips);
    ip_to_str(net.gw, gws);
    ip_to_str(net.mask, msk);
    ip_to_str(net.dns, dns);
    if (net.have_dns2) ip_to_str(net.dns2, dns2);
    LOGI("net ip=%s mask=%s gw=%s dns=%s%s%s", ips, msk, gws, dns,
         net.have_dns2 ? " " : "", dns2);

    if (geteuid() != 0) {
        LOGE("not root: cannot create utun. Re-run with sudo.");
        rndis_halt(dev);
        usb_rndis_close(dev);
        return -1;
    }
    g_utun = utun_create(g_ifname);
    if (g_utun < 0 || !g_ifname[0]) {
        LOGE("utun_create failed");
        rndis_halt(dev);
        usb_rndis_close(dev);
        return -1;
    }
    LOGI("utun %s", g_ifname);
    utun_set_mtu(g_ifname, 1500);
    if (utun_ifconfig(g_ifname, ips, gws, msk) != 0)
        LOGE("ifconfig failed (continuing)");
    route_setup(g_ifname, net.ip, net.mask, net.gw, net.dns,
                net.have_dns2 ? net.dns2 : NULL, !o->no_route, !o->no_dns);

    g_running = 1;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    pthread_t ka, ev, tx;
    /* TX pool first: RX completions (ARP replies) already need it. */
    struct usb_tx_pool *txpool = usb_tx_pool_start(dev, TX_POOL_N, XFER_BUF);
    if (!txpool) {
        LOGE("tx pool start failed");
        route_restore();
        rndis_halt(dev);
        usb_rndis_close(dev);
        return -1;
    }
    struct rx_ctx rctx = {.dev = dev, .txpool = txpool};
    if (usb_rx_pool_start(dev, RX_POOL_N, XFER_BUF, on_usb_frame, &rctx) != 0) {
        LOGE("rx pool start failed");
        usb_tx_pool_stop(txpool);
        route_restore();
        rndis_halt(dev);
        usb_rndis_close(dev);
        return -1;
    }
    struct bridge_ctx bctx = {
        .dev = dev, .txpool = txpool, .max_transfer = max_transfer};
    pthread_create(&ka, NULL, keepalive_thread, dev);
    pthread_create(&ev, NULL, event_thread, dev);
    pthread_create(&tx, NULL, tx_thread, &bctx);

    /* Supervise: idle stats + disconnect detection (watch mode reconnects). */
    LOGI("bridging %s <-> USB tethering (Ctrl-C to stop)", g_ifname);
    time_t t0 = time(NULL), last_log = t0;
    while (g_running) {
        for (int i = 0; i < 4 && g_running; i++) usleep(250000);
        if (!g_running) break;
        if (usb_rx_disconnected(dev)) {
            LOGE("USB device disconnected");
            g_running = 0;
            break;
        }
        if (g_verbose && time(NULL) - last_log >= 15) {
            LOGV("tx %llu pkts %llu bytes drop %llu / rx %llu pkts %llu bytes drop %llu",
                 (unsigned long long)atomic_load(&g_tx_pkts),
                 (unsigned long long)atomic_load(&g_tx_bytes),
                 (unsigned long long)atomic_load(&g_tx_drops),
                 (unsigned long long)atomic_load(&g_rx_pkts),
                 (unsigned long long)atomic_load(&g_rx_bytes),
                 (unsigned long long)atomic_load(&g_rx_drops));
            last_log = time(NULL);
        }
    }

    time_t dt = time(NULL) - t0;
    if (dt < 1) dt = 1;
    LOGI("stop: tx %llu pkts %llu bytes, rx %llu pkts %llu bytes in %lds",
         (unsigned long long)atomic_load(&g_tx_pkts),
         (unsigned long long)atomic_load(&g_tx_bytes),
         (unsigned long long)atomic_load(&g_rx_pkts),
         (unsigned long long)atomic_load(&g_rx_bytes), (long)dt);

    g_running = 0;
    usb_tx_kick(txpool);
    pthread_join(tx, NULL);
    pthread_join(ev, NULL);
    pthread_join(ka, NULL);
    usb_rx_pool_stop(dev);
    usb_tx_pool_stop(txpool);
    route_restore();
    if (g_utun >= 0) {
        utun_close(g_utun);
        g_utun = -1;
    }
    rndis_halt(dev);
    usb_rndis_close(dev);
    return 0;
}

int main(int argc, char **argv) {
    struct opts o;
    memset(&o, 0, sizeof(o));
    ip_from_str("192.168.42.129", o.gateway);
    ip_from_str("255.255.255.0", o.netmask);
    o.have_gateway = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--probe")) o.probe = 1;
        else if (!strcmp(argv[i], "--watch")) o.watch = 1;
        else if (!strcmp(argv[i], "--no-route")) o.no_route = 1;
        else if (!strcmp(argv[i], "--no-dns")) o.no_dns = 1;
        else if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) {
            o.verbose = 1;
            g_verbose = 1;
        } else if (!strcmp(argv[i], "--static") && i + 1 < argc) {
            if (ip_from_str(argv[++i], o.static_ip) != 0) {
                LOGE("bad --static IP");
                return 2;
            }
            o.have_static = 1;
        } else if (!strcmp(argv[i], "--gateway") && i + 1 < argc) {
            if (ip_from_str(argv[++i], o.gateway) != 0) {
                LOGE("bad --gateway");
                return 2;
            }
            o.have_gateway = 1;
        } else if (!strcmp(argv[i], "--netmask") && i + 1 < argc) {
            if (ip_from_str(argv[++i], o.netmask) != 0) {
                LOGE("bad --netmask");
                return 2;
            }
        } else if (!strcmp(argv[i], "--dns") && i + 1 < argc) {
            if (ip_from_str(argv[++i], o.dns) != 0) {
                LOGE("bad --dns");
                return 2;
            }
            o.have_dns = 1;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage();
            return 0;
        } else {
            LOGE("unknown arg %s", argv[i]);
            usage();
            return 2;
        }
    }
    if (o.have_static && !o.have_gateway)
        ip_from_str("192.168.42.129", o.gateway);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (!o.watch) return run_once(&o) == 0 ? 0 : 1;
    while (g_running) {
        g_running = 1;
        g_utun = -1;
        if (run_once(&o) == 0 && o.probe) return 0;
        if (!g_running) break;
        LOGI("watch: retry in 3s...");
        for (int i = 0; i < 30 && g_running; i++) usleep(100000);
    }
    return 0;
}
