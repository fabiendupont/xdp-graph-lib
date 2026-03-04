/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * l2fwd_tx - TX node for L2 forwarder example.
 *
 * Reads metadata, swaps source/destination MAC addresses,
 * and passes the packet back to the kernel stack.
 *
 * In a real deployment, this would use XDP_REDIRECT with a
 * DEVMAP to forward to a specific output interface.
 */

#include "../../src/bpf/xgl_common.bpf.h"

char LICENSE[] SEC("license") = "BSD-3-Clause";

#define ETH_ALEN 6

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __u16         h_proto;
} __attribute__((packed));

XGL_NODE(l2fwd_tx)
{
    struct xgl_meta *meta;
    void *data, *data_end;
    struct ethhdr *eth;
    unsigned char tmp[ETH_ALEN];
    __u32 pkt_len;

    meta = XGL_META_GET(ctx);
    if (!meta) {
        XGL_STATS_INC_ERROR(egl_node_stats, 1);
        XGL_DROP();
    }

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;

    /* Bounds check for Ethernet header */
    if ((void *)(eth + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, 1);
        XGL_DROP();
    }

    pkt_len = (__u32)(data_end - data);

    /* Swap MAC addresses */
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    XGL_STATS_INC_TX(egl_node_stats, 1, pkt_len);

    /* Pass to kernel stack (in production, use XDP_REDIRECT) */
    XGL_PASS();
}
