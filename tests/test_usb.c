/* Fault injection against production USB code: no device or root needed. */
#include <libusb.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int fake_submit(struct libusb_transfer *);
static int fake_cancel(struct libusb_transfer *);
static int fake_events(libusb_context *, struct timeval *, int *);
static int fake_control(libusb_device_handle *, uint8_t, uint8_t, uint16_t,
                        uint16_t, unsigned char *, uint16_t, unsigned int);
static struct libusb_transfer *fake_alloc(int);
static int fake_bulk(libusb_device_handle *, unsigned char, unsigned char *, int, int *, unsigned);
#define libusb_bulk_transfer fake_bulk
#define libusb_submit_transfer fake_submit
#define libusb_cancel_transfer fake_cancel
#define libusb_handle_events_timeout_completed fake_events
#define libusb_control_transfer fake_control
#define libusb_alloc_transfer fake_alloc
#include "../src/usb.c"
#undef libusb_alloc_transfer
int g_verbose = 0;
static struct libusb_transfer *queued[64];
static int queued_n, submit_error, allocation_fail, pumps, delay, input_calls;
static uint32_t request_type, request_xid;
static int response_mode;
static int bulk_length, bulk_last;
static int fake_bulk(libusb_device_handle *h, unsigned char ep, unsigned char *b, int n, int *done, unsigned t) {
    (void)h; (void)ep; (void)t;
    bulk_length = n; bulk_last = b[n-1]; *done = n; return 0;
}
static struct libusb_transfer *fake_alloc(int n) {
    return allocation_fail ? NULL : libusb_alloc_transfer(n);
}
static int fake_submit(struct libusb_transfer *x) {
    if (submit_error) return submit_error;
    assert(queued_n < 64); queued[queued_n++] = x; return 0;
}
static int fake_cancel(struct libusb_transfer *x) {
    x->status = LIBUSB_TRANSFER_CANCELLED; return 0;
}
static int fake_events(libusb_context *c, struct timeval *t, int *done) {
    (void)c; (void)t; (void)done;
    if (++pumps <= delay) return 0;
    if (queued_n) {
        struct libusb_transfer *x = queued[--queued_n];
        x->callback(x);
    }
    return 0;
}
static int fake_control(libusb_device_handle *h, uint8_t type, uint8_t req,
                        uint16_t value, uint16_t idx, unsigned char *b,
                        uint16_t len, unsigned int timeout) {
    (void)h; (void)req; (void)value; (void)idx; (void)timeout;
    if (type == 0x21) { request_type = rd32(b); request_xid = rd32(b + 8); return len; }
    input_calls++;
    memset(b, 0, len);
    wr32(b, request_type | RNDIS_MSG_COMPLETION);
    wr32(b + 8, request_xid);
    if (response_mode == 1) { wr32(b + 4, 16); return 16; } /* short INIT */
    if (response_mode == 2) { /* query pointing into unused buffer */
        wr32(b + 4, 24); wr32(b + 16, 6); wr32(b + 20, 128); return 24;
    }
    wr32(b + 4, 16); return 16;
}
int main(void) {
    struct rndis_usb_dev d = {.max_transfer = 4740, .bulk_in = 0x81, .bulk_out = 1};
    pthread_mutex_init(&d.ctrl_lock, NULL); pthread_mutex_init(&d.rx_lock, NULL);
    atomic_init(&d.rx_disc, 0);
    uint8_t b[CONTROL_BUFFER_SIZE] = {0};
    wr32(b, RNDIS_MSG_HALT); wr32(b + 4, 12);
    assert(rndis_command(&d, b, sizeof(b)) == 0 && input_calls == 0);
    puts("ok HALT does not wait for nonexistent completion");
    response_mode = 1;
    wr32(b, RNDIS_MSG_INIT); wr32(b + 4, 24);
    assert(rndis_command(&d, b, sizeof(b)) == -1);
    puts("ok short INIT completion rejected");
    response_mode = 2;
    void *reply; int n = 6;
    assert(rndis_query(&d, b, 0, 0, &reply, &n) == -1);
    puts("ok QUERY cannot read beyond actual message");
    allocation_fail = 1;
    assert(usb_tx_pool_start(&d, 2, 16384) == NULL);
    allocation_fail = 0;
    puts("ok total TX allocation failure fails promptly");
    struct usb_tx_pool *p = usb_tx_pool_start(&d, 1, 16384);
    size_t cap;
    uint8_t *buf = usb_tx_acquire(p, &cap);
    assert(usb_tx_submit(p, buf, 4741, 100) == -1 && p->active == 0);
    assert(usb_tx_try_acquire(p, &cap) == buf);
    submit_error = LIBUSB_ERROR_IO;
    assert(usb_tx_submit(p, buf, 100, 100) == -1 && p->active == 0);
    submit_error = 0;
    assert(usb_tx_try_acquire(p, &cap) == buf);
    assert(usb_tx_submit(p, buf, 100, 100) == 0 && p->active == 1);
    pumps = 0; delay = 25;
    usb_tx_pool_stop(p);
    assert(queued_n == 0 && pumps > 25);
    puts("ok failed submits recycle slots and cancellation drains beyond 2 seconds");
    pumps = 0;
    assert(usb_rx_pool_start(&d, 2, 16384, NULL, NULL) == 0);
    usb_rx_pool_stop(&d);
    assert(queued_n == 0 && pumps > 25);
    puts("ok RX cancellation waits for every callback");
    delay = 0;
    assert(usb_rx_pool_start(&d, 1, 16384, NULL, NULL) == 0);
    queued[0]->status = LIBUSB_TRANSFER_STALL;
    fake_events(NULL, NULL, NULL);
    assert(usb_rx_disconnected(&d) && d.rx_active == 0);
    usb_rx_pool_stop(&d);
    puts("ok stalled RX requests reconnect without blocking USB in callback");
    atomic_store(&d.rx_disc, 0);
    assert(usb_rx_pool_start(&d, 1, 16384, NULL, NULL) == 0);
    queued[0]->status = LIBUSB_TRANSFER_COMPLETED;
    submit_error = LIBUSB_ERROR_NO_DEVICE;
    fake_events(NULL, NULL, NULL);
    assert(usb_rx_disconnected(&d) && d.rx_active == 0);
    usb_rx_pool_stop(&d);
    puts("ok RX resubmit failure requests reconnect");
    submit_error = 0;
    p = usb_tx_pool_start(&d, 1, 16384);
    buf = usb_tx_acquire(p, &cap);
    uint8_t eth[1514] = {0}; eth[12]=8; eth[14]=0x45;
    struct rndis_batch batch;
    rndis_batch_init(&batch, buf, 4740, 3, 1);
    for (int i=0; i<3; i++) assert(rndis_batch_append(&batch, eth, sizeof(eth))==0);
    assert(usb_tx_submit(p,buf,batch.len,100)==0);
    struct usb_tx_stats stats;
    usb_tx_get_stats(p,&stats);
    assert(stats.bytes==0 && stats.packets==0);
    queued[0]->status=LIBUSB_TRANSFER_COMPLETED;
    queued[0]->actual_length=queued[0]->length;
    fake_events(NULL,NULL,NULL);
    usb_tx_get_stats(p,&stats);
    assert(stats.packets==3 && stats.bytes==4500 && stats.transfers==1 && !stats.errors);
    usb_tx_pool_stop(p);
    puts("ok TX statistics count successful completions and all packets in a batch");
    p = usb_tx_pool_start(&d, 1, 16384);
    buf = usb_tx_acquire(p, &cap);
    memset(buf, 0, 100);
    assert(usb_tx_submit(p, buf, 100, 100) == 0 && p->active == 1);
    queued[0]->status = LIBUSB_TRANSFER_COMPLETED;
    queued[0]->actual_length = queued[0]->length;
    delay = 0;
    pumps = 0;
    struct usb_tx_stats drained = usb_tx_pool_stop(p);
    assert(drained.transfers == 1 && drained.errors == 0 && queued_n == 0);
    puts("ok TX pool stop counts completions that finish during drain");
    for (unsigned packet = 64; packet <= 1024; packet *= 2) {
        d.out_packet_size = packet;
        p = usb_tx_pool_start(&d, 1, 2048);
        buf = usb_tx_acquire(p, &cap);
        assert(rndis_wrap_packet(eth, packet - 44, buf, cap) == packet);
        assert(usb_tx_submit(p, buf, packet, 100) == 0);
        assert(queued[0]->length == (int)packet + 1 && buf[packet] == 0);
        assert(rd32(buf + 4) == packet);
        assert(usb_bulk_out(&d, buf, packet, 100) == 0);
        assert(bulk_length == (int)packet + 1 && bulk_last == 0);
        queued[0]->status = LIBUSB_TRANSFER_COMPLETED;
        queued[0]->actual_length = queued[0]->length;
        usb_tx_pool_stop(p);
    }
    d.out_packet_size = 512;
    p = usb_tx_pool_start(&d, 1, 512);
    buf = usb_tx_acquire(p, &cap);
    assert(usb_tx_submit(p, buf, 512, 100) == -1 && p->active == 0);
    assert(usb_tx_try_acquire(p, &cap) == buf);
    usb_tx_release(p, buf); usb_tx_pool_stop(p);
    d.max_transfer = 4096;
    assert(usb_get_max_transfer(&d) == 4095);
    puts("ok sync/async USB boundary padding, unchanged RNDIS lengths, safe capacity limits");
    pthread_mutex_destroy(&d.ctrl_lock); pthread_mutex_destroy(&d.rx_lock);
    return 0;
}
