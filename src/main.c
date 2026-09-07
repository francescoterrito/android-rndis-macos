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
#include <fcntl.h>
#include <sys/file.h>

#include "usb.h"
#include "utun.h"
#include "rndis.h"
#include "rndis_proto.h"
#include "frame.h"
#include "dhcp.h"
#include "route.h"
#include "net_util.h"
#include "status.h"
#include "log.h"

int g_verbose = 0;

static atomic_int g_running = 1;
static volatile sig_atomic_t g_stop = 0, g_renew_requested = 0;
static _Atomic double g_lease_deadline = 1e100;
static int g_utun = -1;
static char g_ifname[16] = {0};

/* Cross-thread statistics: plain integers would be data races (UB in C11),
 * so all counters are atomic. Writers: event thread (rx), TX thread (tx).
 * Reader: supervision thread after/while running (loads are lock-free). */
static atomic_ullong g_rx_bytes = 0, g_tx_bytes = 0;
static atomic_ullong g_rx_pkts = 0, g_tx_pkts = 0;
static atomic_ullong g_tx_drops = 0, g_rx_drops = 0;
/* Current session identity for status snapshots (empty when idle). */
static char g_cur_ip[16] = {0};
static time_t g_session_start = 0;
static struct status_metrics g_metrics;

static void snap(const char *state) {
    long up = g_session_start ? (long)(time(NULL) - g_session_start) : 0;
    g_metrics.tx_drops = atomic_load(&g_tx_drops);
    g_metrics.rx_drops = atomic_load(&g_rx_drops);
    double remaining = atomic_load(&g_lease_deadline) - net_now();
    g_metrics.lease_remaining = remaining > 0 && remaining < 1e10 ? (long)remaining : 0;
    status_set_metrics(&g_metrics);
    status_write(state, g_cur_ip, g_ifname,
                 (unsigned long long)atomic_load(&g_tx_bytes),
                 (unsigned long long)atomic_load(&g_rx_bytes),
                 (unsigned long long)atomic_load(&g_tx_pkts),
                 (unsigned long long)atomic_load(&g_rx_pkts), up);
}

/* Async pipeline depths. 16 RX transfers keep the IN pipe permanently fed;
 * 32 TX slots absorb bursts with negotiated batching. Buffers are 16KB; no USB
 * transfer may exceed the device's max_transfer_size (4740 on Samsung). */
#define RX_POOL_N 16
#define TX_POOL_N 32
#define XFER_BUF 16384

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
    int single_tx;
};

static void usage(void) {
    fprintf(stderr,
            "usage: android-rndis-macos [options]\n"
            "  --probe            list USB + RNDIS handshake only, no network changes\n"
            "  --watch            reconnect automatically when phone appears\n"
            "  --no-route         don't touch default route\n"
            "  --no-dns           don't touch DNS settings\n"
            "  --static IP        skip DHCP, use this IP\n"
            "  --gateway IP       gateway for --static (default 192.168.42.129)\n"
            "  --netmask IP       (default 255.255.255.0)\n"
            "  --dns IP           (default = gateway)\n"
            "  --single-tx        disable negotiated TX batching (diagnostic)\n"
            "  --verbose          debug logging\n");
}

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    g_running = 0;
}

static void on_renew_signal(int sig) { (void)sig; g_renew_requested = 1; }

static int install_stop_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) return -1;
    sa.sa_handler = on_renew_signal;
    if (sigaction(SIGUSR1, &sa, NULL)) return -1;
    /* Privileged launchers can pass a blocked signal mask to children. */
    sigset_t stops;
    sigemptyset(&stops); sigaddset(&stops, SIGINT); sigaddset(&stops, SIGTERM); sigaddset(&stops, SIGUSR1);
    return pthread_sigmask(SIG_UNBLOCK, &stops, NULL);
}

static void *keepalive_thread(void *arg) {
    struct rndis_usb_dev *dev = arg;
    int failures = 0;
    while (g_running) {
        for (int i = 0; i < 50 && g_running; i++) usleep(100000);
        if (!g_running) break;
        if (rndis_keepalive(dev) == 0) failures = 0;
        else if (++failures >= 3) {
            LOGE("RNDIS keepalive failed repeatedly; reconnecting");
            g_running = 0;
        }
    }
    return NULL;
}

struct rx_ctx {
    struct rndis_usb_dev *dev;
    struct usb_tx_pool *txpool; /* reserved pool for ARP and DHCP */
    struct dhcp_client dhcp;
    pthread_mutex_t dhcp_lock;
    int use_dhcp;
};

struct bridge_ctx {
    struct rndis_usb_dev *dev;
    struct usb_tx_pool *txpool;
    size_t max_transfer;
    unsigned max_packets, alignment;
};

static const uint8_t kBroadcastMac[6] = {255, 255, 255, 255, 255, 255};

static int submit_eth(struct usb_tx_pool *p, const uint8_t *eth, size_t n) {
    if (!p || !eth || !n) return -1;
    size_t cap = 0;
    uint8_t *buf = usb_tx_try_acquire(p, &cap);
    if (!buf) return -1;
    size_t wn = rndis_wrap_packet(eth, n, buf, cap);
    if (!wn) {
        usb_tx_release(p, buf);
        return -1;
    }
    return usb_tx_submit(p, buf, wn, 1000) == 0 ? 0 : -1;
}

static int send_gateway_arp(struct usb_tx_pool *p) {
    uint8_t arp[42];
    size_t n = frame_build_arp_request(arp, sizeof(arp));
    return n ? submit_eth(p, arp, n) : -1;
}

static int peer_mac_unresolved(void) {
    uint8_t mac[6];
    frame_get_peer(mac, NULL);
    return mac[0] & 1;
}

static void deliver_frame(const uint8_t *eth, size_t len, void *ctx) {
    struct rx_ctx *c = ctx;
    /* Only UDP/67->68 takes the DHCP lock, never ordinary traffic. */
    if (c->use_dhcp && len >= 42 && eth[12] == 8 && eth[13] == 0 && eth[23] == 17) {
        size_t ihl = (eth[14] & 15) * 4;
        if (ihl >= 20 && len >= 14 + ihl + 8 &&
            get_be16(eth + 14 + ihl) == 67 && get_be16(eth + 16 + ihl) == 68) {
            pthread_mutex_lock(&c->dhcp_lock);
            int received = dhcp_client_receive(&c->dhcp, eth, len, net_now());
            if (received == 2) {
                atomic_store(&g_lease_deadline, c->dhcp.expires_at);
            }
            pthread_mutex_unlock(&c->dhcp_lock);
            if (received < 0) { LOGE("DHCP lease invalidated; reacquiring"); g_running = 0; }
            return; /* DHCP belongs to this client, not the Mac IP stack. */
        }
    }
    if (!g_running || net_now() >= atomic_load(&g_lease_deadline)) return;
    const uint8_t *ipbuf = NULL;
    size_t iplen = 0;
    uint8_t reply[42];
    size_t rlen = 0;
    int r = frame_handle_view(eth, len, &ipbuf, &iplen, reply,
                            sizeof(reply), &rlen);
    if (rlen && c->dev && c->txpool) {
        /* Runs on the event thread: blocking USB calls are forbidden here
         * (libusb returns BUSY), so answer via the async TX pool. */
        if (submit_eth(c->txpool, reply, rlen) != 0)
            atomic_fetch_add(&g_tx_drops, 1ULL);
    }
    if (r == 1) {
        if (g_utun >= 0 && utun_write_ip(g_utun, ipbuf, iplen) == 0) {
            atomic_fetch_add(&g_rx_bytes, (unsigned long long)iplen);
            atomic_fetch_add(&g_rx_pkts, 1ULL);
        } else {
            atomic_fetch_add(&g_rx_drops, 1ULL);
        }
    } else if (r < 0) {
        atomic_fetch_add(&g_rx_drops, 1ULL);
    }
}

/* Runs on the USB event thread (serialized). */
static void on_usb_frame(uint8_t *buf, size_t len, void *ctx) {
    int n = rndis_unwrap_packets(buf, len, deliver_frame, ctx);
    if (n < 0) {
        LOGV("rx framing error (%zu bytes)", len);
        atomic_fetch_add(&g_rx_drops, 1ULL);
    }
}

static void *event_thread(void *arg) {
    struct rndis_usb_dev *dev = arg;
    while (g_running) {
        if (usb_handle_events(dev, 250) != 0) g_running = 0;
    }
    return NULL;
}

/* Read directly into the final USB transfer, after the reserved RNDIS and
 * Ethernet headers. No read-ahead unless a full MTU frame fits. */
static void *tx_thread(void *arg) {
    struct bridge_ctx *b = arg;
    while (g_running) {
        struct pollfd pfd = {.fd = g_utun, .events = POLLIN};
        int ready = poll(&pfd, 1, 100);
        if (!g_running) break;
        if (ready < 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) { g_running = 0; break; }
        if (!ready) continue;
        size_t cap;
        uint8_t *buf = usb_tx_acquire(b->txpool, &cap);
        if (!buf) break;
        if (cap > b->max_transfer) cap = b->max_transfer;
        struct rndis_batch batch;
        rndis_batch_init(&batch, buf, cap, b->max_packets, b->alignment);
        uint8_t *eth;
        while (g_running && (eth = rndis_batch_reserve(&batch, 1514))) {
            if (net_now() >= atomic_load(&g_lease_deadline)) { g_running = 0; break; }
            int len = utun_read_ip(g_utun, eth + 14, 1500);
            if (len < 0) {
                atomic_fetch_add(&g_tx_drops, 1ULL);
                break;
            }
            if (len == 0) break;
            size_t n = frame_wrap_out(eth + 14, (size_t)len, eth, 1514);
            if (!n || rndis_batch_append(&batch, eth, n) != 0) {
                atomic_fetch_add(&g_tx_drops, 1); break;
            }
        }
        if (!batch.packets || !g_running) { usb_tx_release(b->txpool, buf); continue; }
        int rc = usb_tx_submit(b->txpool, buf, batch.len, 2000);
        if (rc != 0) atomic_fetch_add(&g_tx_drops, batch.packets);
        if (rc == -2) g_running = 0;
    }
    return NULL;
}
static void update_tx_stats(struct usb_tx_pool *p) {
    struct usb_tx_stats s;
    usb_tx_get_stats(p, &s);
    atomic_store(&g_tx_bytes, s.bytes); atomic_store(&g_tx_pkts, s.packets);
    g_metrics.tx_transfers = s.transfers; g_metrics.tx_errors = s.errors;
}

static int session_cancelled(void *ctx) {
    struct opts *o = ctx;
    return g_stop || (o->watch && !auto_enabled());
}

static int run_once(struct opts *o) {
    struct rndis_usb_dev *dev = NULL;
    const struct usb_match *m = NULL;
    struct usb_tx_pool *txpool = NULL, *controlpool = NULL;
    pthread_t ka, ev, tx;
    int have_ka = 0, have_ev = 0, have_tx = 0, bound = 0, rc = -1;
    struct rx_ctx rctx = {.dhcp_lock = PTHREAD_MUTEX_INITIALIZER};
    struct bridge_ctx bctx = {0};
    g_running = !g_stop;
    g_renew_requested = 0;
    atomic_store(&g_lease_deadline, 1e100);
    memset(&g_metrics, 0, sizeof(g_metrics));
    g_ifname[0] = g_cur_ip[0] = 0;
    g_session_start = 0;
    atomic_store(&g_rx_bytes, 0); atomic_store(&g_tx_bytes, 0);
    atomic_store(&g_rx_pkts, 0); atomic_store(&g_tx_pkts, 0);
    atomic_store(&g_rx_drops, 0); atomic_store(&g_tx_drops, 0);
    if (!o->probe) snap("waiting for phone");
    if (session_cancelled(o) || usb_find_rndis(&dev, &m) != 0) goto cleanup;
    if (!o->probe) snap("connecting");
    if (usb_rndis_claim(dev) != 0) goto cleanup;
    uint8_t dev_mac[6] = {0};
    uint32_t max_transfer = XFER_BUF;
    if (rndis_bind_seq(dev, dev_mac, &max_transfer) != 0) goto cleanup;
    bound = 1;
    char macs[18]; mac_to_str(dev_mac, macs);
    LOGI("RNDIS bound mac=%s max_transfer=%u %s", macs, max_transfer,
         m ? m->desc : "");
    if (o->probe) { rc = 0; goto cleanup; }
    if (session_cancelled(o)) goto cleanup;

    uint8_t our_mac[6];
    memcpy(our_mac, dev_mac, 6);
    /* RNDIS supplies the host address, not the phone gateway address. */
    struct dhcp_result net = {0};
    uint8_t peer[6];
    memset(peer, 0xff, 6); /* Broadcast until DHCP/ARP supplies the gateway MAC. */
    if (o->have_static) {
        memcpy(net.ip, o->static_ip, 4);
        memcpy(net.mask, o->netmask, 4);
        memcpy(net.gw, o->gateway, 4);
        memcpy(net.dns, o->gateway, 4);
    } else {
        LOGI("DHCP discover...");
        if (dhcp_run(dev, our_mac, &net, peer, 15, session_cancelled, o) != 0) {
            LOGE("DHCP failed; leaving network unchanged");
            goto cleanup;
        }
    }
    if (!o->have_static) {
        if (dhcp_client_start(&rctx.dhcp, &net, arc4random()) != 0) goto cleanup;
        rctx.use_dhcp = 1;
        atomic_store(&g_lease_deadline, rctx.dhcp.expires_at);
    }
    if (o->have_dns) { memcpy(net.dns, o->dns, 4); net.have_dns2 = 0; }
    if (session_cancelled(o)) goto cleanup;
    frame_init(our_mac, net.ip);
    frame_set_peer(peer, net.gw);

    char ips[16], gws[16], msk[16];
    ip_to_str(net.ip, ips); ip_to_str(net.gw, gws); ip_to_str(net.mask, msk);
    g_utun = utun_create(g_ifname);
    if (g_utun < 0 || !g_ifname[0]) { LOGE("utun_create failed"); goto cleanup; }
    if (utun_set_mtu(g_ifname, 1500) != 0 ||
        utun_ifconfig(g_ifname, ips, gws, msk) != 0) {
        LOGE("interface configuration failed"); goto cleanup;
    }
    txpool = usb_tx_pool_start(dev, TX_POOL_N, XFER_BUF);
    if (!txpool) { LOGE("tx pool start failed"); goto cleanup; }
    controlpool = usb_tx_pool_start(dev, 4, 2048);
    if (!controlpool) goto cleanup;
    rctx.dev = dev; rctx.txpool = controlpool;
    if (usb_rx_pool_start(dev, RX_POOL_N, XFER_BUF, on_usb_frame, &rctx) != 0)
        goto cleanup;
    bctx = (struct bridge_ctx){.dev = dev, .txpool = txpool, .max_transfer = max_transfer,
        .max_packets = o->single_tx ? 1 : usb_get_max_packets(dev),
        .alignment = usb_get_alignment(dev)};
    LOGI("TX pipeline: up to %u packets per transfer, %u-byte alignment",
         bctx.max_packets, bctx.alignment);
    if (pthread_create(&ev, NULL, event_thread, dev) != 0) goto cleanup;
    have_ev = 1;
    if (pthread_create(&tx, NULL, tx_thread, &bctx) != 0) goto cleanup;
    have_tx = 1;
    if (pthread_create(&ka, NULL, keepalive_thread, dev) != 0) goto cleanup;
    have_ka = 1;
    if (session_cancelled(o) || route_setup(g_ifname, net.ip, net.mask, net.gw,
            net.dns, net.have_dns2 ? net.dns2 : NULL, !o->no_route, !o->no_dns) != 0)
        goto cleanup;
    struct sigaction action;
    if (sigaction(SIGTERM, NULL, &action) == 0 && action.sa_handler != on_signal)
        LOGE("SIGTERM handler changed during setup; restoring it");
    if (install_stop_handlers() != 0) goto cleanup;
    strncpy(g_cur_ip, ips, sizeof(g_cur_ip) - 1);
    g_session_start = time(NULL);
    snap("connected");
    LOGI("bridging %s <-> USB tethering", g_ifname);
    /* RX is running, so the ARP reply can be learned. Static mode starts
     * with a broadcast destination until this resolves. */
    (void)send_gateway_arp(controlpool);
    rc = 0;
    unsigned applied_renewals = 0;
    int tick = 0;
    while (g_running && !session_cancelled(o)) {
        usleep(250000);
        if (usb_rx_disconnected(dev)) { LOGE("USB transport lost; reconnecting"); rc = -1; break; }
        if (rctx.use_dhcp) {
            uint8_t request[600], peer_now[6];
            frame_get_peer(peer_now, NULL);
            pthread_mutex_lock(&rctx.dhcp_lock);
            double now = net_now();
            if (g_renew_requested) { dhcp_client_renew_now(&rctx.dhcp, now); g_renew_requested = 0; }
            enum dhcp_phase before = rctx.dhcp.phase;
            int n = dhcp_client_tick(&rctx.dhcp, now, peer_now, request, sizeof(request));
            enum dhcp_phase phase = rctx.dhcp.phase;
            struct dhcp_result renewed = rctx.dhcp.net;
            unsigned count = rctx.dhcp.renewals;
            pthread_mutex_unlock(&rctx.dhcp_lock);
            if (n < 0) { LOGE("DHCP lease expired; reacquiring"); rc = -1; break; }
            if (phase != before) LOGI("DHCP %s", phase == DHCP_REBINDING ? "rebinding" : "renewing");
            if (n > 0 && submit_eth(controlpool, request, (size_t)n) != 0) {
                pthread_mutex_lock(&rctx.dhcp_lock);
                rctx.dhcp.next_request = now + 1;
                pthread_mutex_unlock(&rctx.dhcp_lock);
            }
            if (count != applied_renewals) {
                if (o->have_dns) { memcpy(renewed.dns, o->dns, 4); renewed.have_dns2 = 0; }
                int gw_change = memcmp(net.gw, renewed.gw, 4) != 0;
                int mask_change = memcmp(net.mask, renewed.mask, 4) != 0;
                if (gw_change || mask_change) {
                    ip_to_str(renewed.gw, gws); ip_to_str(renewed.mask, msk);
                    if (utun_ifconfig(g_ifname, ips, gws, msk) != 0) { rc = -1; break; }
                    if (gw_change) {
                        /* Old gateway MAC is not valid for a new next hop. */
                        frame_set_peer(kBroadcastMac, renewed.gw);
                        (void)send_gateway_arp(controlpool);
                    }
                }
                if (gw_change || mask_change || memcmp(net.dns, renewed.dns, 4) ||
                    net.have_dns2 != renewed.have_dns2 || memcmp(net.dns2, renewed.dns2, 4)) {
                    if (route_update(g_ifname, renewed.ip, renewed.mask, renewed.gw,
                        renewed.dns, renewed.have_dns2 ? renewed.dns2 : NULL,
                        !o->no_route, !o->no_dns) != 0) { rc = -1; break; }
                }
                net = renewed;
                applied_renewals = count;
                g_metrics.renewals = count;
                LOGI("DHCP renewed in place (%u), lease=%us; %s stays up", count, net.lease_sec, g_ifname);
            }
        }
        if (++tick % 4 == 0) {
            update_tx_stats(txpool);
            snap("connected");
            if (peer_mac_unresolved()) (void)send_gateway_arp(controlpool);
            if (tick % 60 == 0) LOGV("traffic tx=%llu rx=%llu dropped tx=%llu rx=%llu",
                (unsigned long long)atomic_load(&g_tx_bytes), (unsigned long long)atomic_load(&g_rx_bytes),
                (unsigned long long)atomic_load(&g_tx_drops), (unsigned long long)atomic_load(&g_rx_drops));
        }
    }
    if (!session_cancelled(o)) rc = -1;
cleanup:
    g_running = 0;
    /* Withdraw routes before stopping packet delivery. */
    route_restore();
    if (txpool) usb_tx_kick(txpool);
    if (controlpool) usb_tx_kick(controlpool);
    if (have_tx) pthread_join(tx, NULL);
    if (have_ka) pthread_join(ka, NULL);
    if (have_ev) pthread_join(ev, NULL);
    if (dev) usb_rx_pool_stop(dev);
    struct usb_tx_stats txstats = usb_tx_pool_stop(txpool);
    atomic_store(&g_tx_bytes, txstats.bytes);
    atomic_store(&g_tx_pkts, txstats.packets);
    g_metrics.tx_transfers = txstats.transfers;
    g_metrics.tx_errors = txstats.errors;
    usb_tx_pool_stop(controlpool);
    pthread_mutex_destroy(&rctx.dhcp_lock);
    if (g_utun >= 0) { utun_close(g_utun); g_utun = -1; }
    if (bound) rndis_halt(dev);
    usb_rndis_close(dev);
    g_session_start = 0; g_cur_ip[0] = g_ifname[0] = 0;
    atomic_store(&g_lease_deadline, 1e100);
    if (!o->probe) snap(session_cancelled(o) ? "off" : "waiting for phone");
    return rc;
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
        else if (!strcmp(argv[i], "--single-tx")) o.single_tx = 1;
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

    if (install_stop_handlers() != 0) { LOGE("cannot install signal handlers"); return 1; }

    int lockfd = -1;
    if (!o.probe) {
        if (geteuid() != 0) { LOGE("run with sudo (or use --probe)"); return 1; }
        lockfd = open("/var/run/android-rndis-macos.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (lockfd < 0 || flock(lockfd, LOCK_EX | LOCK_NB) != 0) {
            LOGE("another daemon is running, or the session lock is unavailable");
            if (lockfd >= 0) close(lockfd);
            return 1;
        }
    }
    int rc = 0;
    do {
        if (session_cancelled(&o)) break;
        rc = run_once(&o);
        if (!o.watch || o.probe || session_cancelled(&o)) break;
        /* Retry independently of the just-ended bridge's stop flag. */
        for (int i = 0; i < 10 && !session_cancelled(&o); i++) usleep(100000);
    } while (!g_stop);
    if (!o.probe) snap("off");
    if (lockfd >= 0) close(lockfd);
    return (g_stop || (o.watch && !auto_enabled())) ? 0 : (rc == 0 ? 0 : 1);
}
