/* USB matching + RNDIS control/data plane over libusb.
 * Control logic is a userspace port of Linux rndis_command/rndis_query/
 * generic_rndis_bind (drivers/net/usb/rndis_host.c, GPL-2.0-or-later).
 */
#include "usb.h"
#include "rndis.h"
#include "rndis_proto.h"
#include "log.h"
#include <libusb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

struct rx_slot {
    struct libusb_transfer *xfer;
    uint8_t *buf;
};

const struct usb_match kRndisMatches[] = {
    {0x1630, 0x0042, 0x02, 0x02, 0xff, 0x01, "2Wire HomePortal"},
    {0x238b, 0x0000, 0x02, 0x02, 0xff, 0x00, "Hytera RNDIS"},
    {0x19d2, 0x0000, 0xe0, 0x01, 0x03, 0x02, "ZTE WWAN"},
    {0x19d2, 0x0000, 0x02, 0x02, 0xff, 0x02, "ZTE WWAN ACM"},
    {0x1bc7, 0x7030, 0xe0, 0x01, 0x03, 0x00, "Telit RNDIS"},
    {0x0000, 0x0000, 0x02, 0x02, 0xff, 0x00, "RNDIS generic ACM"},
    {0x0000, 0x0000, 0xe0, 0x01, 0x03, 0x00, "RNDIS tethering"},
    {0x0000, 0x0000, 0xef, 0x01, 0x01, 0x00, "ActiveSync"},
    {0x0000, 0x0000, 0xef, 0x04, 0x01, 0x00, "Novatel USB730L"},
};
const size_t kRndisMatchCount = sizeof(kRndisMatches) / sizeof(kRndisMatches[0]);

struct rndis_usb_dev {
    libusb_context *ctx;
    libusb_device_handle *h;
    int ctrl_if;
    int data_if;
    uint8_t bulk_in, bulk_out, intr_in;
    unsigned quirks;
    uint8_t mac[6];
    uint32_t max_transfer;
    pthread_mutex_t ctrl_lock;
    uint16_t vid, pid;
    /* async RX pool */
    struct rx_slot *rx_slots;
    int rx_n;
    size_t rx_size;
    usb_rx_cb rx_cb;
    void *rx_ctx;
    pthread_mutex_t rx_lock;
    int rx_active;
    int rx_stop;
    atomic_int rx_disc;
};

static const struct usb_match *match_if(uint16_t vid, uint16_t pid,
                                        int cls, int sub, int proto) {
    for (size_t i = 0; i < kRndisMatchCount; i++) {
        const struct usb_match *m = &kRndisMatches[i];
        if (m->vid && m->vid != vid) continue;
        if (m->pid && m->pid != pid) continue;
        if (m->cls != cls || m->sub != sub || m->proto != proto) continue;
        return m;
    }
    return NULL;
}

/* Scan one device: find control iface matching table + data iface with bulks. */
static int scan_device(libusb_device *dev, int *ctrl_if, int *data_if,
                       uint8_t *bulk_in, uint8_t *bulk_out, uint8_t *intr_in,
                       const struct usb_match **mp, uint16_t *vid, uint16_t *pid) {
    struct libusb_device_descriptor dd;
    if (libusb_get_device_descriptor(dev, &dd) != 0) return -1;
    *vid = dd.idVendor;
    *pid = dd.idProduct;

    struct libusb_config_descriptor *cfg = NULL;
    if (libusb_get_active_config_descriptor(dev, &cfg) != 0) {
        if (libusb_get_config_descriptor(dev, 0, &cfg) != 0) return -1;
    }
    int found_ctrl = -1, found_data = -1;
    uint8_t bi = 0, bo = 0, ii = 0;
    const struct usb_match *found_m = NULL;

    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *iface = &cfg->interface[i];
        for (int a = 0; a < iface->num_altsetting; a++) {
            const struct libusb_interface_descriptor *d = &iface->altsetting[a];
            const struct usb_match *m =
                match_if(dd.idVendor, dd.idProduct, d->bInterfaceClass,
                         d->bInterfaceSubClass, d->bInterfaceProtocol);
            if (m && found_ctrl < 0) {
                found_ctrl = d->bInterfaceNumber;
                found_m = m;
                for (int e = 0; e < d->bNumEndpoints; e++) {
                    const struct libusb_endpoint_descriptor *ep = &d->endpoint[e];
                    uint8_t addr = ep->bEndpointAddress;
                    uint8_t attr = ep->bmAttributes & 0x03;
                    if ((addr & 0x80) && attr == 0x03) ii = addr;
                }
            }
        }
    }
    /* Data iface: prefer ctrl+1 with 2 bulks, else any iface with 2 bulks. */
    for (int pass = 0; pass < 2 && found_ctrl >= 0 && found_data < 0; pass++) {
        for (int i = 0; i < cfg->bNumInterfaces; i++) {
            const struct libusb_interface *iface = &cfg->interface[i];
            for (int a = 0; a < iface->num_altsetting; a++) {
                const struct libusb_interface_descriptor *d = &iface->altsetting[a];
                if (pass == 0 && d->bInterfaceNumber != found_ctrl + 1) continue;
                uint8_t t_in = 0, t_out = 0;
                for (int e = 0; e < d->bNumEndpoints; e++) {
                    const struct libusb_endpoint_descriptor *ep = &d->endpoint[e];
                    if ((ep->bmAttributes & 0x03) != 0x02) continue;
                    if (ep->bEndpointAddress & 0x80)
                        t_in = ep->bEndpointAddress;
                    else
                        t_out = ep->bEndpointAddress;
                }
                if (t_in && t_out) {
                    found_data = d->bInterfaceNumber;
                    bi = t_in;
                    bo = t_out;
                    goto done;
                }
            }
        }
    }
done:
    libusb_free_config_descriptor(cfg);
    if (found_ctrl < 0 || found_data < 0) return -1;
    *ctrl_if = found_ctrl;
    *data_if = found_data;
    *bulk_in = bi;
    *bulk_out = bo;
    *intr_in = ii;
    *mp = found_m;
    return 0;
}

int usb_find_rndis(struct rndis_usb_dev **out, const struct usb_match **match) {
    libusb_context *ctx = NULL;
    if (libusb_init(&ctx) != 0) {
        LOGE("libusb_init failed");
        return -1;
    }
    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    if (n < 0) {
        libusb_exit(ctx);
        return -1;
    }
    struct rndis_usb_dev *dev = NULL;
    const struct usb_match *m = NULL;
    for (ssize_t i = 0; i < n && !dev; i++) {
        int ci = -1, di = -1;
        uint8_t bi = 0, bo = 0, ii = 0;
        uint16_t vid = 0, pid = 0;
        const struct usb_match *mm = NULL;
        if (scan_device(list[i], &ci, &di, &bi, &bo, &ii, &mm, &vid,
                        &pid) != 0)
            continue;
        libusb_device_handle *h = NULL;
        int rc = libusb_open(list[i], &h);
        if (rc != 0) {
            LOGV("usb %04x:%04x matched %s but open failed: %s", vid, pid,
                 mm ? mm->desc : "?", libusb_strerror(rc));
            continue;
        }
        dev = calloc(1, sizeof(*dev));
        if (!dev) {
            libusb_close(h);
            break;
        }
        dev->ctx = ctx;
        dev->h = h;
        dev->ctrl_if = ci;
        dev->data_if = di;
        dev->bulk_in = bi;
        dev->bulk_out = bo;
        dev->intr_in = ii;
        dev->quirks = mm ? mm->quirks : 0;
        dev->vid = vid;
        dev->pid = pid;
        dev->max_transfer = 16384;
        pthread_mutex_init(&dev->ctrl_lock, NULL);
        pthread_mutex_init(&dev->rx_lock, NULL);
        atomic_init(&dev->rx_disc, 0);
        m = mm;
        LOGI("found %s USB %04x:%04x ctrl=%d data=%d bulk %02x/%02x intr %02x",
             mm->desc, vid, pid, ci, di, bi, bo, ii);
    }
    libusb_free_device_list(list, 1);
    if (!dev) {
        libusb_exit(ctx);
        LOGE("no Android RNDIS device found (enable USB tethering first)");
        return -1;
    }
    if (out) *out = dev;
    if (match) *match = m;
    return 0;
}

void usb_list_all(void) {
    libusb_context *ctx = NULL;
    if (libusb_init(&ctx) != 0) return;
    libusb_device **list = NULL;
    ssize_t n = libusb_get_device_list(ctx, &list);
    for (ssize_t i = 0; i < n; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0) continue;
        LOGI("usb %04x:%04x class %02x", dd.idVendor, dd.idProduct,
             dd.bDeviceClass);
    }
    libusb_free_device_list(list, 1);
    libusb_exit(ctx);
}

int usb_rndis_claim(struct rndis_usb_dev *dev) {
    libusb_set_auto_detach_kernel_driver(dev->h, 1);
    int rc = libusb_claim_interface(dev->h, dev->ctrl_if);
    if (rc != 0) {
        LOGE("claim ctrl %d: %s (try sudo)", dev->ctrl_if,
             libusb_strerror(rc));
        return -1;
    }
    if (dev->data_if != dev->ctrl_if) {
        rc = libusb_claim_interface(dev->h, dev->data_if);
        if (rc != 0) {
            LOGE("claim data %d: %s", dev->data_if, libusb_strerror(rc));
            libusb_release_interface(dev->h, dev->ctrl_if);
            return -1;
        }
    }
    return 0;
}

void usb_rndis_close(struct rndis_usb_dev *dev) {
    if (!dev) return;
    if (dev->h) {
        libusb_release_interface(dev->h, dev->ctrl_if);
        if (dev->data_if != dev->ctrl_if)
            libusb_release_interface(dev->h, dev->data_if);
        libusb_close(dev->h);
    }
    if (dev->ctx) libusb_exit(dev->ctx);
    pthread_mutex_destroy(&dev->ctrl_lock);
    pthread_mutex_destroy(&dev->rx_lock);
    free(dev->rx_slots);
    free(dev);
}

/* --- RNDIS control plane --- */

static uint32_t rd32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return le32toh(v);
}
static void wr32(uint8_t *p, uint32_t v) {
    uint32_t l = htole32(v);
    memcpy(p, &l, 4);
}

int rndis_command(struct rndis_usb_dev *dev, uint8_t *buf, size_t buflen) {
    if (buflen < CONTROL_BUFFER_SIZE) return -1;
    uint32_t req_type = rd32(buf);
    uint32_t req_len = rd32(buf + 4);
    uint32_t xid = 0;
    if (req_type != RNDIS_MSG_HALT && req_type != RNDIS_MSG_RESET) {
        xid = rndis_next_xid();
        wr32(buf + 8, xid);
    }
    pthread_mutex_lock(&dev->ctrl_lock);
    int rc = libusb_control_transfer(dev->h, 0x21, USB_CDC_SEND_ENCAPSULATED_COMMAND,
                                     0, (uint16_t)dev->ctrl_if, buf, (uint16_t)req_len,
                                     RNDIS_CONTROL_TIMEOUT_MS);
    if (rc < 0) {
        LOGV("SEND_ENCAP failed: %s", libusb_strerror(rc));
        pthread_mutex_unlock(&dev->ctrl_lock);
        return -1;
    }
    if ((dev->quirks & 0x01) && dev->intr_in) {
        uint8_t notif[8];
        int got = 0;
        libusb_interrupt_transfer(dev->h, dev->intr_in, notif, sizeof(notif),
                                  &got, 200);
    }
    uint32_t want = req_type | RNDIS_MSG_COMPLETION;
    int ret = -1;
    for (int i = 0; i < 10; i++) {
        memset(buf, 0, buflen);
        rc = libusb_control_transfer(dev->h, 0xA1, USB_CDC_GET_ENCAPSULATED_RESPONSE,
                                     0, (uint16_t)dev->ctrl_if, buf,
                                     (uint16_t)buflen, RNDIS_CONTROL_TIMEOUT_MS);
        if (rc < 8) {
            usleep(40000);
            continue;
        }
        uint32_t mt = rd32(buf), ml = rd32(buf + 4), rid = rd32(buf + 8),
                 st = rd32(buf + 12);
        (void)ml;
        if (mt == want) {
            if (rid != xid) {
                LOGV("xid mismatch got %u want %u", rid, xid);
                usleep(40000);
                continue;
            }
            if (want == RNDIS_MSG_RESET_C) {
                ret = 0;
                break;
            }
            if (st == RNDIS_STATUS_SUCCESS) {
                ret = 0;
                break;
            }
            LOGV("rndis status %08x", st);
            ret = -1;
            break;
        }
        if (mt == RNDIS_MSG_INDICATE) {
            LOGV("INDICATE %08x", st);
            continue;
        }
        if (mt == RNDIS_MSG_KEEPALIVE) {
            /* Reply KEEPALIVE_C like Linux does. */
            uint8_t ka[16];
            memset(ka, 0, sizeof(ka));
            wr32(ka, RNDIS_MSG_KEEPALIVE_C);
            wr32(ka + 4, sizeof(ka));
            wr32(ka + 8, rid);
            wr32(ka + 12, RNDIS_STATUS_SUCCESS);
            libusb_control_transfer(dev->h, 0x21, USB_CDC_SEND_ENCAPSULATED_COMMAND,
                                    0, (uint16_t)dev->ctrl_if, ka, sizeof(ka), 1000);
            continue;
        }
        LOGV("unexpected rndis msg %08x", mt);
        usleep(40000);
    }
    pthread_mutex_unlock(&dev->ctrl_lock);
    return ret;
}

int rndis_query(struct rndis_usb_dev *dev, uint8_t *buf, uint32_t oid,
                uint32_t in_len, void **reply, int *reply_len) {
    memset(buf, 0, CONTROL_BUFFER_SIZE);
    wr32(buf, RNDIS_MSG_QUERY);
    wr32(buf + 4, 28 + in_len);
    wr32(buf + 12, oid);
    wr32(buf + 16, in_len);
    wr32(buf + 20, 20);
    /* extra in_len bytes after header stay zero (ActiveSync pad quirk) */
    if (rndis_command(dev, buf, CONTROL_BUFFER_SIZE) != 0) return -1;
    uint32_t off = rd32(buf + 20), len = rd32(buf + 16);
    if (off > CONTROL_BUFFER_SIZE - 8 || len > CONTROL_BUFFER_SIZE - 8 - off)
        return -1;
    if (*reply_len != -1 && (int)len != *reply_len) {
        LOGV("query %08x len %u != want %d", oid, len, *reply_len);
        return -1;
    }
    *reply = buf + 8 + off;
    *reply_len = (int)len;
    return 0;
}

int rndis_bind_seq(struct rndis_usb_dev *dev, uint8_t mac[6],
                   uint32_t *max_transfer) {
    uint8_t *buf = calloc(1, CONTROL_BUFFER_SIZE);
    if (!buf) return -1;

    /* INIT 1.0, like Linux generic_rndis_bind. */
    memset(buf, 0, CONTROL_BUFFER_SIZE);
    wr32(buf, RNDIS_MSG_INIT);
    wr32(buf + 4, 24);
    wr32(buf + 12, RNDIS_MAJOR_VERSION);
    wr32(buf + 16, RNDIS_MINOR_VERSION);
    wr32(buf + 20, 16384);
    if (rndis_command(dev, buf, CONTROL_BUFFER_SIZE) != 0) {
        LOGE("RNDIS INIT failed (is USB tethering enabled?)");
        free(buf);
        return -1;
    }
    uint32_t dev_max = rd32(buf + 36);
    LOGV("INIT ok dev_max=%u align=%u", dev_max, rd32(buf + 40));
    if (dev_max >= 1518 + 44 && dev_max < 16384) dev->max_transfer = dev_max;

    /* PHYSICAL_MEDIUM is optional. */
    {
        void *r = NULL;
        int rl = 4;
        if (rndis_query(dev, buf, RNDIS_OID_GEN_PHYSICAL_MEDIUM, 4, &r, &rl) == 0)
            LOGV("physical medium %u", rd32((uint8_t *)r));
    }
    /* Permanent MAC, 48-byte pad for ActiveSync quirk. */
    {
        void *r = NULL;
        int rl = 6;
        if (rndis_query(dev, buf, RNDIS_OID_802_3_PERMANENT_ADDRESS, 48, &r,
                        &rl) != 0) {
            LOGE("QUERY MAC failed");
            free(buf);
            return -1;
        }
        memcpy(mac, r, 6);
        memcpy(dev->mac, r, 6);
    }
    if (rndis_set_packet_filter(dev, RNDIS_DEFAULT_FILTER) != 0) {
        LOGE("SET packet filter failed");
        free(buf);
        return -1;
    }
    if (max_transfer) *max_transfer = dev->max_transfer;
    free(buf);
    return 0;
}

int rndis_set_packet_filter(struct rndis_usb_dev *dev, uint32_t filter) {
    uint8_t buf[CONTROL_BUFFER_SIZE];
    memset(buf, 0, sizeof(buf));
    wr32(buf, RNDIS_MSG_SET);
    wr32(buf + 4, 4 + 28);
    wr32(buf + 12, RNDIS_OID_GEN_CURRENT_PACKET_FILTER);
    wr32(buf + 16, 4);
    wr32(buf + 20, 20);
    wr32(buf + 28, filter);
    return rndis_command(dev, buf, sizeof(buf));
}

int rndis_halt(struct rndis_usb_dev *dev) {
    uint8_t buf[CONTROL_BUFFER_SIZE];
    memset(buf, 0, sizeof(buf));
    wr32(buf, RNDIS_MSG_HALT);
    wr32(buf + 4, 12);
    (void)rndis_command(dev, buf, sizeof(buf));
    return 0;
}

int rndis_keepalive(struct rndis_usb_dev *dev) {
    uint8_t buf[CONTROL_BUFFER_SIZE];
    memset(buf, 0, sizeof(buf));
    wr32(buf, RNDIS_MSG_KEEPALIVE);
    wr32(buf + 4, 12);
    return rndis_command(dev, buf, sizeof(buf));
}

int usb_bulk_out(struct rndis_usb_dev *dev, const uint8_t *buf, size_t len,
                 unsigned timeout_ms) {
    int done = 0;
    int rc = libusb_bulk_transfer(dev->h, dev->bulk_out, (uint8_t *)buf,
                                  (int)len, &done, timeout_ms);
    if (rc != 0 || (size_t)done != len) {
        LOGV("bulk-OUT %s", libusb_strerror(rc));
        return -1;
    }
    return 0;
}

int usb_bulk_in(struct rndis_usb_dev *dev, uint8_t *buf, size_t cap,
                size_t *got, unsigned timeout_ms) {
    int done = 0;
    int rc = libusb_bulk_transfer(dev->h, dev->bulk_in, buf, (int)cap, &done,
                                  timeout_ms);
    if (rc == LIBUSB_ERROR_TIMEOUT) {
        if (got) *got = 0;
        return 0;
    }
    if (rc != 0) {
        LOGV("bulk-IN %s", libusb_strerror(rc));
        return -1;
    }
    if (got) *got = (size_t)done;
    return 0;
}

void usb_get_addrs(struct rndis_usb_dev *dev, int *ctrl_if, int *data_if,
                   uint8_t *bulk_in, uint8_t *bulk_out, uint8_t *intr_in) {
    if (ctrl_if) *ctrl_if = dev->ctrl_if;
    if (data_if) *data_if = dev->data_if;
    if (bulk_in) *bulk_in = dev->bulk_in;
    if (bulk_out) *bulk_out = dev->bulk_out;
    if (intr_in) *intr_in = dev->intr_in;
}

unsigned usb_get_quirks(struct rndis_usb_dev *dev) { return dev->quirks; }

void usb_get_mac(struct rndis_usb_dev *dev, uint8_t mac[6]) {
    memcpy(mac, dev->mac, 6);
}

size_t usb_get_max_transfer(struct rndis_usb_dev *dev) {
    return dev->max_transfer;
}

int usb_handle_events(struct rndis_usb_dev *dev, int timeout_ms) {
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int rc = libusb_handle_events_timeout_completed(dev->ctx, &tv, NULL);
    return (rc == 0 || rc == LIBUSB_ERROR_TIMEOUT ||
            rc == LIBUSB_ERROR_INTERRUPTED)
               ? 0
               : -1;
}

/* --- Async RX pool --- */

static void LIBUSB_CALL rx_complete(struct libusb_transfer *xfer) {
    struct rndis_usb_dev *dev = xfer->user_data;
    int resubmit = 0;

    switch (xfer->status) {
    case LIBUSB_TRANSFER_COMPLETED:
        if (xfer->actual_length > 0 && dev->rx_cb)
            dev->rx_cb(xfer->buffer, (size_t)xfer->actual_length, dev->rx_ctx);
        resubmit = !dev->rx_stop;
        break;
    case LIBUSB_TRANSFER_NO_DEVICE:
        atomic_store(&dev->rx_disc, 1);
        break;
    case LIBUSB_TRANSFER_CANCELLED:
        break;
    case LIBUSB_TRANSFER_STALL:
        libusb_clear_halt(dev->h, dev->bulk_in);
        resubmit = !dev->rx_stop;
        break;
    default: /* TIMEOUT/ERROR/OVERFLOW: retry while running */
        resubmit = !dev->rx_stop;
        break;
    }

    if (resubmit && libusb_submit_transfer(xfer) == 0) return;

    /* terminal path: exactly one decrement per submitted transfer */
    xfer->user_data = NULL;
    pthread_mutex_lock(&dev->rx_lock);
    dev->rx_active--;
    pthread_mutex_unlock(&dev->rx_lock);
}

int usb_rx_pool_start(struct rndis_usb_dev *dev, int n, size_t xfer_size,
                      usb_rx_cb cb, void *ctx) {
    pthread_mutex_lock(&dev->rx_lock);
    dev->rx_slots = calloc((size_t)n, sizeof(struct rx_slot));
    if (!dev->rx_slots) {
        pthread_mutex_unlock(&dev->rx_lock);
        return -1;
    }
    dev->rx_n = n;
    dev->rx_size = xfer_size;
    dev->rx_cb = cb;
    dev->rx_ctx = ctx;
    dev->rx_stop = 0;
    atomic_store(&dev->rx_disc, 0);
    int ok = 0;
    for (int i = 0; i < n; i++) {
        uint8_t *buf = malloc(xfer_size);
        struct libusb_transfer *x = buf ? libusb_alloc_transfer(0) : NULL;
        if (!buf || !x) {
            free(buf);
            if (x) libusb_free_transfer(x);
            continue;
        }
        dev->rx_slots[i].buf = buf;
        dev->rx_slots[i].xfer = x;
        libusb_fill_bulk_transfer(x, dev->h, dev->bulk_in, buf, (int)xfer_size,
                                  rx_complete, dev, 0);
        if (libusb_submit_transfer(x) == 0) {
            dev->rx_active++;
            ok++;
        } else {
            libusb_free_transfer(x);
            free(buf);
            dev->rx_slots[i].xfer = NULL;
            dev->rx_slots[i].buf = NULL;
        }
    }
    pthread_mutex_unlock(&dev->rx_lock);
    LOGI("rx pool: %d/%d async transfers in flight (%zu B each)", ok, n,
         xfer_size);
    return ok > 0 ? 0 : -1;
}

void usb_rx_pool_stop(struct rndis_usb_dev *dev) {
    pthread_mutex_lock(&dev->rx_lock);
    dev->rx_stop = 1;
    for (int i = 0; i < dev->rx_n; i++) {
        if (dev->rx_slots && dev->rx_slots[i].xfer &&
            dev->rx_slots[i].xfer->user_data)
            libusb_cancel_transfer(dev->rx_slots[i].xfer);
    }
    pthread_mutex_unlock(&dev->rx_lock);
    /* drain: pump events until every transfer reports back (max ~2s).
     * Caller must have joined the event thread first. */
    for (int i = 0; i < 20; i++) {
        pthread_mutex_lock(&dev->rx_lock);
        int active = dev->rx_active;
        pthread_mutex_unlock(&dev->rx_lock);
        if (active <= 0) break;
        usb_handle_events(dev, 100);
    }
    pthread_mutex_lock(&dev->rx_lock);
    if (dev->rx_slots) {
        for (int i = 0; i < dev->rx_n; i++) {
            if (dev->rx_slots[i].xfer) libusb_free_transfer(dev->rx_slots[i].xfer);
            free(dev->rx_slots[i].buf);
        }
        free(dev->rx_slots);
        dev->rx_slots = NULL;
    }
    dev->rx_n = 0;
    dev->rx_active = 0;
    pthread_mutex_unlock(&dev->rx_lock);
}

int usb_rx_disconnected(struct rndis_usb_dev *dev) {
    return atomic_load(&dev->rx_disc);
}

/* --- Async TX pool --- */

struct tx_slot {
    struct libusb_transfer *xfer;
    uint8_t *buf;
    size_t size;
    int in_use;
};

struct usb_tx_pool {
    struct rndis_usb_dev *dev;
    struct tx_slot *slots;
    int n;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int stop;
    int active;
};

static void LIBUSB_CALL tx_complete(struct libusb_transfer *xfer) {
    struct usb_tx_pool *p = xfer->user_data;
    if (!p) return;
    if (xfer->status == LIBUSB_TRANSFER_NO_DEVICE)
        atomic_store(&p->dev->rx_disc, 1);
    else if (xfer->status == LIBUSB_TRANSFER_STALL)
        libusb_clear_halt(p->dev->h, p->dev->bulk_out);
    pthread_mutex_lock(&p->lock);
    for (int i = 0; i < p->n; i++) {
        if (p->slots[i].xfer == xfer) {
            p->slots[i].in_use = 0;
            break;
        }
    }
    p->active--;
    pthread_cond_signal(&p->cond);
    pthread_mutex_unlock(&p->lock);
}

struct usb_tx_pool *usb_tx_pool_start(struct rndis_usb_dev *dev, int n,
                                      size_t buf_size) {
    struct usb_tx_pool *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->slots = calloc((size_t)n, sizeof(struct tx_slot));
    if (!p->slots) {
        free(p);
        return NULL;
    }
    p->dev = dev;
    p->n = n;
    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->cond, NULL);
    for (int i = 0; i < n; i++) {
        p->slots[i].buf = malloc(buf_size);
        p->slots[i].xfer = p->slots[i].buf ? libusb_alloc_transfer(0) : NULL;
        p->slots[i].size = buf_size;
        if (!p->slots[i].buf || !p->slots[i].xfer) {
            free(p->slots[i].buf);
            if (p->slots[i].xfer) libusb_free_transfer(p->slots[i].xfer);
            p->slots[i].buf = NULL;
            p->slots[i].xfer = NULL;
        }
    }
    return p;
}

uint8_t *usb_tx_acquire(struct usb_tx_pool *p, size_t *cap_out) {
    pthread_mutex_lock(&p->lock);
    for (;;) {
        if (p->stop) {
            pthread_mutex_unlock(&p->lock);
            return NULL;
        }
        for (int i = 0; i < p->n; i++) {
            if (p->slots[i].xfer && !p->slots[i].in_use) {
                p->slots[i].in_use = 1;
                if (cap_out) *cap_out = p->slots[i].size;
                uint8_t *b = p->slots[i].buf;
                pthread_mutex_unlock(&p->lock);
                return b;
            }
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&p->cond, &p->lock, &ts);
    }
}

uint8_t *usb_tx_try_acquire(struct usb_tx_pool *p, size_t *cap_out) {
    pthread_mutex_lock(&p->lock);
    uint8_t *found = NULL;
    if (!p->stop) {
        for (int i = 0; i < p->n; i++) {
            if (p->slots[i].xfer && !p->slots[i].in_use) {
                p->slots[i].in_use = 1;
                if (cap_out) *cap_out = p->slots[i].size;
                found = p->slots[i].buf;
                break;
            }
        }
    }
    pthread_mutex_unlock(&p->lock);
    return found;
}

void usb_tx_release(struct usb_tx_pool *p, uint8_t *buf) {
    pthread_mutex_lock(&p->lock);
    for (int i = 0; i < p->n; i++) {
        if (p->slots[i].buf == buf) {
            p->slots[i].in_use = 0;
            break;
        }
    }
    pthread_cond_signal(&p->cond);
    pthread_mutex_unlock(&p->lock);
}

int usb_tx_submit(struct usb_tx_pool *p, uint8_t *buf, size_t len,
                  unsigned timeout_ms) {
    struct tx_slot *slot = NULL;
    pthread_mutex_lock(&p->lock);
    for (int i = 0; i < p->n; i++) {
        if (p->slots[i].buf == buf) {
            slot = &p->slots[i];
            break;
        }
    }
    pthread_mutex_unlock(&p->lock);
    if (!slot || !slot->in_use) return -1;
    libusb_fill_bulk_transfer(slot->xfer, p->dev->h, p->dev->bulk_out, buf,
                              (int)len, tx_complete, p, timeout_ms);
    int rc = libusb_submit_transfer(slot->xfer);
    if (rc == LIBUSB_ERROR_NO_DEVICE) {
        usb_tx_release(p, buf);
        return -2;
    }
    if (rc != 0) {
        usb_tx_release(p, buf);
        return -1;
    }
    pthread_mutex_lock(&p->lock);
    p->active++;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

void usb_tx_kick(struct usb_tx_pool *p) {
    pthread_mutex_lock(&p->lock);
    p->stop = 1;
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->lock);
}

void usb_tx_pool_stop(struct usb_tx_pool *p) {
    if (!p) return;
    pthread_mutex_lock(&p->lock);
    p->stop = 1;
    pthread_cond_broadcast(&p->cond);
    for (int i = 0; i < p->n; i++) {
        if (p->slots[i].xfer && p->slots[i].in_use)
            libusb_cancel_transfer(p->slots[i].xfer);
    }
    pthread_mutex_unlock(&p->lock);
    /* drain via caller's event pumping (event thread already joined:
     * pump here directly) */
    for (int i = 0; i < 20; i++) {
        pthread_mutex_lock(&p->lock);
        int active = p->active;
        pthread_mutex_unlock(&p->lock);
        if (active <= 0) break;
        usb_handle_events(p->dev, 100);
    }
    for (int i = 0; i < p->n; i++) {
        if (p->slots[i].xfer) libusb_free_transfer(p->slots[i].xfer);
        free(p->slots[i].buf);
    }
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p->slots);
    free(p);
}
