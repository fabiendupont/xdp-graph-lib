/* SPDX-License-Identifier: BSD-2-Clause */

#include "xgl_common.bpf.h"

char LICENSE[] SEC("license") = "BSD-3-Clause";

/*
 * xgl_dispatch - Root dispatcher node.
 *
 * This is the entry point for the XDP graph pipeline. It:
 * 1. Allocates metadata in XDP headroom via XGL_META_ALLOC()
 * 2. Sets ingress_ifindex and timestamp_ns
 * 3. Tail-calls to node index 0 (the first processing node)
 * 4. Falls back to XDP_DROP if the tail call fails
 */
XGL_NODE(xgl_dispatch)
{
    struct xgl_meta *meta = XGL_META_ALLOC(ctx);

    if (!meta)
        XGL_DROP();

    meta->ingress_ifindex = ctx->ingress_ifindex;
    meta->timestamp_ns = bpf_ktime_get_ns();
    meta->next_node = 0;

    XGL_STATS_INC_RX(egl_node_stats, 0,
                     ctx->data_end - ctx->data);

    XGL_NEXT(ctx, egl_prog_array, 0);

    /* Tail call failed — drop the packet */
    XGL_DROP();
}
