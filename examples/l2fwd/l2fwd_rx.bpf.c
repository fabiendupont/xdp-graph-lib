/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * l2fwd_rx - Root node for L2 forwarder example.
 *
 * Allocates metadata, records ingress info, and tail-calls to
 * the TX node (index 1).
 */

#include <xgl/bpf/xgl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

#define TX_NODE_INDEX 1

XGL_NODE(l2fwd_rx)
{
    struct xgl_meta *meta;

    meta = XGL_META_ALLOC(ctx);
    if (!meta)
        XGL_DROP();

    meta->ingress_ifindex = ctx->ingress_ifindex;
    meta->timestamp_ns = bpf_ktime_get_ns();
    meta->l2_proto = 0; /* Will be parsed by downstream node */
    meta->next_node = TX_NODE_INDEX;

    /* Length is computed at the point of use: hoisting the
     * subtraction above the ktime call makes clang spill the packet
     * pointer across the helper call, and PREVAIL loses the region
     * type through the spill/reload (xdp/l2fwd_rx FAIL). */
    XGL_STATS_INC_RX(egl_node_stats, 0, ctx->data_end - ctx->data);

    XGL_NEXT(ctx, egl_prog_array, TX_NODE_INDEX);

    /* Tail call failed — pass to kernel stack */
    XGL_STATS_INC_ERROR(egl_node_stats, 0);
    XGL_PASS();
}
