/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_EDGES_BPF_H
#define XGL_EDGES_BPF_H

#include <linux/types.h>

/*
 * XGL_EDGE — declare a node's tail-call targets in the BPF object.
 *
 * The declared edges are stored in a custom ".xgl.edges" ELF section
 * that the kernel ignores but the loader (and offline checkers) read.
 * This makes the node's control flow part of its metadata:
 *
 *   - xgl_graph_add_node() auto-ingests the section and registers
 *     the edges in the graph — a cycle formed by code-declared
 *     edges fails node addition with -ELOOP instead of being
 *     discovered (or not) at runtime.
 *   - tools/xgl_edges extracts the section so xgl_check can
 *     validate the *actual* call graph, not just declared edges.
 *
 * Usage (one per possible tail-call target):
 *
 *   XGL_NODE(my_node)
 *   {
 *       ...
 *       XGL_NEXT(ctx, egl_prog_array, 2);
 *       XGL_DROP();
 *   }
 *   XGL_EDGE("my_node", 2);
 *
 * For nodes that dispatch dynamically via meta->next_node, the set
 * of targets cannot be enumerated statically.  Declare the wildcard
 * instead; the loader warns and the checker treats the node as
 * "may call any slot":
 *
 *   XGL_EDGE_DYNAMIC("my_dispatch_node");
 *
 * Notes:
 *   - prog must be a string literal; it ties the entry to the
 *     program in the same object (one node per object is the
 *     convention, but the name makes multi-program objects safe).
 *   - The section is little-endian packed data like the rest of a
 *     BPF ELF object.
 */

#define XGL_EDGE_DYNAMIC_SENTINEL 0xFFFFFFFFU

struct xgl_edge_meta {
    char  prog[32];
    __u32 to;
} __attribute__((packed, aligned(4)));

#define XGL_EDGE_CAT_(a, b) a ## b
#define XGL_EDGE_CAT(a, b) XGL_EDGE_CAT_(a, b)

#define XGL_EDGE_IMPL(_prog, _to, _id)                               \
    static const struct xgl_edge_meta                                \
        XGL_EDGE_CAT(__xgl_edge_, _id)                               \
    __attribute__((used, section(".xgl.edges"), aligned(4))) = {     \
        .prog = (_prog),                                             \
        .to   = (_to),                                               \
    }

/* Declare a static tail-call target: XGL_EDGE("my_node", 2); */
#define XGL_EDGE(prog, to) \
    XGL_EDGE_IMPL(prog, to, __COUNTER__)

/* Declare dynamic dispatch (meta->next_node): may call any slot. */
#define XGL_EDGE_DYNAMIC(prog) \
    XGL_EDGE_IMPL(prog, XGL_EDGE_DYNAMIC_SENTINEL, __COUNTER__)

#endif /* XGL_EDGES_BPF_H */
