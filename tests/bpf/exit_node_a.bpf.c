/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * exit_node_a - test node with a named exit.
 *
 * Declares one symbolic exit ("next"); the node's code tail-calls
 * through it without knowing the slot.  The loader binds
 * "next" to a slot via xgl_graph_bind_exit() and patches the
 * call-site immediate before loading.
 */

#include <xgl/bpf/xgl_common.bpf.h>

char LICENSE[] SEC("license") = "BSD-3-Clause";

XGL_EXIT_TAG(next);

XGL_NODE(exit_node_a)
{
    XGL_EXIT(ctx, egl_prog_array, next);

    /* Tail call failed — drop. */
    XGL_DROP();
}
