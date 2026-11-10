/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * edge_node_a - test node with declared tail-call metadata.
 * Declares static edges to slots 2 and 3, and dynamic dispatch.
 */

#include <xgl/bpf/xgl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

XGL_NODE(edge_node_a)
{
    XGL_DROP();
}

XGL_EDGE("edge_node_a", 2);
XGL_EDGE("edge_node_a", 3);
XGL_EDGE_DYNAMIC("edge_node_a");
