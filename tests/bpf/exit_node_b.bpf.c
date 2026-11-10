/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * exit_node_b - terminal test node: increments RX stats for slot 2
 * and passes the packet up.  Used as the binding target of
 * exit_node_a's "next" exit; observing its stats proves the patched
 * tail call reached the bound slot.
 */

#include <xgl/bpf/xgl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

#define NODE_ID 2

XGL_NODE(exit_node_b)
{
    XGL_STATS_INC_RX(egl_node_stats, NODE_ID, 64);
    XGL_PASS();
}
