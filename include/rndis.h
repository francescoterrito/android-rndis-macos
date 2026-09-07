/* Ported from Linux include/linux/rndis.h + include/linux/usb/rndis_host.h
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Original: Copyright (C) 2005 by David Brownell, Linux drivers/net/usb/rndis_host.c
 *
 * Changes vs kernel version: __le32 -> uint32_t, packed structs kept,
 * endian helpers via htole32/le32toh below (macOS: OSSwap).
 */
#ifndef CABLED_HOTSPOT_RNDIS_H
#define CABLED_HOTSPOT_RNDIS_H

#include <stdint.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#else
#include <endian.h>
#endif

#define RNDIS_MAJOR_VERSION 0x00000001
#define RNDIS_MINOR_VERSION 0x00000000

#define RNDIS_DF_CONNECTIONLESS  0x00000001U
#define RNDIS_DF_CONNECTION_ORIENTED 0x00000002U

#define RNDIS_MSG_COMPLETION 0x80000000
#define RNDIS_MSG_PACKET  0x00000001
#define RNDIS_MSG_INIT    0x00000002
#define RNDIS_MSG_INIT_C  (RNDIS_MSG_INIT|RNDIS_MSG_COMPLETION)
#define RNDIS_MSG_HALT    0x00000003
#define RNDIS_MSG_QUERY   0x00000004
#define RNDIS_MSG_QUERY_C (RNDIS_MSG_QUERY|RNDIS_MSG_COMPLETION)
#define RNDIS_MSG_SET     0x00000005
#define RNDIS_MSG_SET_C   (RNDIS_MSG_SET|RNDIS_MSG_COMPLETION)
#define RNDIS_MSG_RESET   0x00000006
#define RNDIS_MSG_RESET_C (RNDIS_MSG_RESET|RNDIS_MSG_COMPLETION)
#define RNDIS_MSG_INDICATE 0x00000007
#define RNDIS_MSG_KEEPALIVE 0x00000008
#define RNDIS_MSG_KEEPALIVE_C (RNDIS_MSG_KEEPALIVE|RNDIS_MSG_COMPLETION)

#define RNDIS_STATUS_SUCCESS 0x00000000
#define RNDIS_STATUS_PENDING 0x00000103
#define RNDIS_STATUS_MEDIA_CONNECT 0x4001000B
#define RNDIS_STATUS_MEDIA_DISCONNECT 0x4001000C
#define RNDIS_STATUS_FAILURE 0xC0000001

#define RNDIS_PHYSICAL_MEDIUM_UNSPECIFIED 0x00000000
#define RNDIS_PHYSICAL_MEDIUM_WIRELESS_LAN 0x00000001
#define RNDIS_PHYSICAL_MEDIUM_WIRELESS_WAN 0x00000008

#define RNDIS_MEDIUM_802_3 0x00000000

#define RNDIS_PACKET_TYPE_DIRECTED    0x00000001
#define RNDIS_PACKET_TYPE_MULTICAST   0x00000002
#define RNDIS_PACKET_TYPE_ALL_MULTICAST 0x00000004
#define RNDIS_PACKET_TYPE_BROADCAST   0x00000008
#define RNDIS_PACKET_TYPE_PROMISCUOUS 0x00000020

#define RNDIS_DEFAULT_FILTER ( \
    RNDIS_PACKET_TYPE_DIRECTED | \
    RNDIS_PACKET_TYPE_BROADCAST | \
    RNDIS_PACKET_TYPE_ALL_MULTICAST | \
    RNDIS_PACKET_TYPE_PROMISCUOUS)

/* OIDs needed for bind (full list in Linux include/linux/rndis.h) */
#define RNDIS_OID_GEN_PHYSICAL_MEDIUM      0x00010202
#define RNDIS_OID_GEN_CURRENT_PACKET_FILTER 0x0001010E
#define RNDIS_OID_802_3_PERMANENT_ADDRESS  0x01010101
#define RNDIS_OID_802_3_CURRENT_ADDRESS    0x01010102
#define RNDIS_OID_GEN_MAXIMUM_FRAME_SIZE   0x00010106
#define RNDIS_OID_GEN_LINK_SPEED           0x00010107
#define RNDIS_OID_GEN_MEDIA_CONNECT_STATUS 0x00010114

#define RNDIS_MEDIA_STATE_CONNECTED    0x00000000
#define RNDIS_MEDIA_STATE_DISCONNECTED 0x00000001

/* Control channel per CDC: SEND/GET_ENCAPSULATED_COMMAND on control iface */
#define USB_CDC_SEND_ENCAPSULATED_COMMAND 0x00
#define USB_CDC_GET_ENCAPSULATED_RESPONSE 0x01

#define CONTROL_BUFFER_SIZE 1025
#define RNDIS_CONTROL_TIMEOUT_MS (5 * 1000)

/* Quirks mirroring Linux driver_info->data */
#define RNDIS_QUIRK_POLL_STATUS  0x01 /* poll interrupt EP before control-IN */
#define RNDIS_QUIRK_DST_MAC_FIXUP 0x02 /* ZTE: device ignores set MAC */

struct rndis_msg_hdr {
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t status;
} __attribute__((packed));

struct rndis_data_hdr {
    uint32_t msg_type;      /* RNDIS_MSG_PACKET */
    uint32_t msg_len;
    uint32_t data_offset;   /* 36 -- right after header */
    uint32_t data_len;
    uint32_t oob_data_offset;
    uint32_t oob_data_len;
    uint32_t num_oob;
    uint32_t packet_data_offset;
    uint32_t packet_data_len;
    uint32_t vc_handle;
    uint32_t reserved;
} __attribute__((packed));

struct rndis_init { /* OUT */
    uint32_t msg_type;
    uint32_t msg_len;       /* 24 */
    uint32_t request_id;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t max_transfer_size;
} __attribute__((packed));

struct rndis_init_c { /* IN */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t status;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t device_flags;
    uint32_t medium;
    uint32_t max_packets_per_message;
    uint32_t max_transfer_size;
    uint32_t packet_alignment;
    uint32_t af_list_offset;
    uint32_t af_list_size;
} __attribute__((packed));

struct rndis_halt { /* OUT, no reply */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
} __attribute__((packed));

struct rndis_query { /* OUT */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t oid;
    uint32_t len;
    uint32_t offset;
    uint32_t handle;
} __attribute__((packed));

struct rndis_query_c { /* IN */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t status;
    uint32_t len;
    uint32_t offset;
} __attribute__((packed));

struct rndis_set { /* OUT */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t oid;
    uint32_t len;
    uint32_t offset;
    uint32_t handle;
} __attribute__((packed));

struct rndis_set_c { /* IN */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t status;
} __attribute__((packed));

struct rndis_indicate { /* IN (unrequested) */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t status;
    uint32_t length;
    uint32_t offset;
    uint32_t diag_status;
    uint32_t error_offset;
    uint32_t message;
} __attribute__((packed));

struct rndis_keepalive { /* OUT */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
} __attribute__((packed));

struct rndis_keepalive_c { /* IN */
    uint32_t msg_type;
    uint32_t msg_len;
    uint32_t request_id;
    uint32_t status;
} __attribute__((packed));

#endif
