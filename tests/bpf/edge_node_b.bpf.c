/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * edge_node_b - test node whose declared edge back to slot 1 forms
 * a cycle with edge_node_a (slot 1 -> 2).  Used to verify that
 * add_node rejects code-declared cycles.
 */

#include <xgl/bpf/xgl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

XGL_NODE(edge_node_b)
{
    XGL_DROP();
}

XGL_EDGE("edge_node_b", 1);
