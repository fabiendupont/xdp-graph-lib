/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_EXITS_BPF_H
#define XGL_EXITS_BPF_H

#include <bpf/bpf_helpers.h>

#include <xgl/xgl_exits.h>

/*
 * XGL_EXIT — symbolic tail-call exits with composition-time binding.
 *
 * A node should not hardcode PROG_ARRAY slot numbers: they are
 * graph-local state, which couples the node to one slot layout and
 * prevents reuse (the model grout solves with named next_nodes).
 * Named exits give nodes the same portability while keeping the
 * zero-overhead tail call: the node code references a *name*, the
 * loader rewrites the call-site immediate to the bound slot before
 * loading (instruction patching — no runtime map lookup).
 *
 * Usage:
 *
 *   XGL_EXIT_TAG(parse);          // file scope, once per exit
 *
 *   XGL_NODE(my_node)
 *   {
 *       ...
 *       XGL_EXIT(ctx, egl_prog_array, parse);   // symbolic
 *       XGL_DROP();             // tail call failed (bad slot/empty)
 *   }
 *
 * The graph binds names to slots before adding the node:
 *
 *   xgl_graph_bind_exit(g, "my_node", "parse", 5);
 *   xgl_graph_add_node(g, 1, "my_node.bpf.o", "my_node");
 *
 * add_node fails with -ENOENT if a declared exit has no binding.
 *
 * Mechanics: XGL_EXIT emits bpf_tail_call with a magic immediate
 * (0x7Exxxxxx | id).  The magic is distinctive enough that the
 * patcher can find call sites by scanning for it; it rewrites the
 * immediate in a copy of the object (graph-owned temp dir) before
 * handing it to the loader.  The kernel never sees the magic.
 *
 * One node per object file is the convention; exit names are scoped
 * to the object.
 */

/*
 * XGL_EXIT_TAG(name) - declare an exit, at file scope.
 *
 * Defines the exit's id (unique within the object, via __COUNTER__)
 * and its .xgl.exits metadata entry used by the loader and offline
 * checkers.  The enum constant lets XGL_EXIT reference the same id
 * without a second __COUNTER__ evaluation.
 */
#define XGL_EXIT_TAG(nm)                                                \
    enum { __xgl_exit_id_##nm = __COUNTER__ };                          \
    static const struct xgl_exit_meta __xgl_exit_meta_##nm              \
    __attribute__((used, section(".xgl.exits"), aligned(4))) = {        \
        .name = #nm,                                                    \
        .id   = __xgl_exit_id_##nm,                                     \
    }

/*
 * XGL_EXIT(ctx, map, name) - tail-call through a named exit.
 *
 * Returns on failure (like XGL_NEXT); follow with a fallback action.
 */
#define XGL_EXIT(ctx_, map_, nm)                                        \
    bpf_tail_call(ctx_, &(map_),                                        \
                  (int)(XGL_EXIT_MAGIC_BASE | __xgl_exit_id_##nm))

#endif /* XGL_EXITS_BPF_H */
