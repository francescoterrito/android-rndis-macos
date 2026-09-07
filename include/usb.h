#ifndef CABLED_HOTSPOT_USB_H
#define CABLED_HOTSPOT_USB_H

#include <stdint.h>
#include <stddef.h>

/* Mirrors Linux rndis_host.c products[] match table. */
struct usb_match {
    uint16_t vid;      /* 0 = any */
    uint16_t pid;      /* 0 = any */
    int cls, sub, proto;
    unsigned quirks;   /* RNDIS_QUIRK_* */
    const char *desc;
};

extern const struct usb_match kRndisMatches[];
extern const size_t kRndisMatchCount;

struct rndis_usb_dev; /* opaque libusb handle + endpoints */

/* Find first matching RNDIS device (returns 0, fills out+match) or -1. */
int usb_find_rndis(struct rndis_usb_dev **out, const struct usb_match **match);
/* List all USB devices with RNDIS-match info (for --probe --verbose). */
void usb_list_all(void);
int usb_rndis_claim(struct rndis_usb_dev *dev);
void usb_rndis_close(struct rndis_usb_dev *dev);

/* Control plane (port of Linux rndis_command/rndis_query/generic_rndis_bind
 * onto libusb_control_transfer). buf must be >= 1025 bytes. */
int rndis_command(struct rndis_usb_dev *dev, uint8_t *buf, size_t buflen);
int rndis_query(struct rndis_usb_dev *dev, uint8_t *buf,
                uint32_t oid, uint32_t in_len,
                void **reply, int *reply_len);
int rndis_bind_seq(struct rndis_usb_dev *dev, uint8_t mac[6],
                   uint32_t *max_transfer);
int rndis_set_packet_filter(struct rndis_usb_dev *dev, uint32_t filter);
int rndis_halt(struct rndis_usb_dev *dev);
int rndis_keepalive(struct rndis_usb_dev *dev);

/* Data plane. Timeouts in ms. Returns 0 on success. */
int usb_bulk_out(struct rndis_usb_dev *dev, const uint8_t *buf, size_t len,
                 unsigned timeout_ms);
int usb_bulk_in(struct rndis_usb_dev *dev, uint8_t *buf, size_t cap,
                size_t *got, unsigned timeout_ms);

/* Accessors for bridge/DHCP layers. */
void usb_get_addrs(struct rndis_usb_dev *dev, int *ctrl_if, int *data_if,
                   uint8_t *bulk_in, uint8_t *bulk_out, uint8_t *intr_in);
unsigned usb_get_quirks(struct rndis_usb_dev *dev);
void usb_get_mac(struct rndis_usb_dev *dev, uint8_t mac[6]);
size_t usb_get_max_transfer(struct rndis_usb_dev *dev);
unsigned usb_get_max_packets(struct rndis_usb_dev *dev);
unsigned usb_get_alignment(struct rndis_usb_dev *dev);
struct usb_tx_pool;
struct usb_tx_stats { uint64_t packets, bytes, transfers, errors; };
void usb_tx_get_stats(struct usb_tx_pool *p, struct usb_tx_stats *out);

/* --- Async streaming pools (performance path, used after DHCP) ---
 * Synchronous bulk transfers cap throughput at ~1 transfer per USB round
 * trip. The pools keep N transfers permanently in flight so the bus never
 * idles. Completion callbacks run on whichever thread calls usb_handle_events
 * (use exactly one event thread: callbacks are then serialized). */
typedef void (*usb_rx_cb)(uint8_t *buf, size_t len, void *ctx);
int usb_rx_pool_start(struct rndis_usb_dev *dev, int n, size_t xfer_size,
                      usb_rx_cb cb, void *ctx);
void usb_rx_pool_stop(struct rndis_usb_dev *dev);
int usb_rx_disconnected(struct rndis_usb_dev *dev);
int usb_handle_events(struct rndis_usb_dev *dev, int timeout_ms);

struct usb_tx_pool;
struct usb_tx_pool *usb_tx_pool_start(struct rndis_usb_dev *dev, int n,
                                      size_t buf_size);
/* Acquire a free buffer (blocks while full; NULL after kick/stop). */
uint8_t *usb_tx_acquire(struct usb_tx_pool *p, size_t *cap_out);
/* Non-blocking variant for event-thread callbacks (NULL if none free). */
uint8_t *usb_tx_try_acquire(struct usb_tx_pool *p, size_t *cap_out);
void usb_tx_release(struct usb_tx_pool *p, uint8_t *buf);
/* Submit a filled buffer. Returns 0 ok, -1 dropped, -2 device gone. */
int usb_tx_submit(struct usb_tx_pool *p, uint8_t *buf, size_t len,
                  unsigned timeout_ms);
void usb_tx_kick(struct usb_tx_pool *p);
/* Cancel in-flight work, drain completions, and return the final counters. */
struct usb_tx_stats usb_tx_pool_stop(struct usb_tx_pool *p);

#endif
