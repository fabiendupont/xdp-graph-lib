/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Privileged integration test: code-declared edges are auto-ingested
 * by xgl_graph_add_node, and a cycle formed by declared edges is
 * rejected at node-addition time with -ELOOP.
 *
 * Skips without CAP_BPF (CI).
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include <xgl/xgl_graph.h>

#ifndef EDGE_OBJ_DIR
#define EDGE_OBJ_DIR "."
#endif

#define OBJ_A EDGE_OBJ_DIR "/edge_node_a.bpf.o"
#define OBJ_B EDGE_OBJ_DIR "/edge_node_b.bpf.o"

static int have_bpf(void)
{
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "probe",
                            sizeof(__u32), sizeof(__u32), 1, NULL);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

int main(void)
{
    struct xgl_graph *g;
    int err;
    int dynamic_logged = 0;

    if (!have_bpf()) {
        printf("SKIP: no CAP_BPF\n");
        return 77;
    }

    g = xgl_graph_create("edge-ingest-test", 0);
    if (!g) {
        printf("FAIL: graph create\n");
        return 1;
    }

    xgl_graph_set_dynamic_edge_logger(g, NULL);
    /* use a capture via simple global */
    (void)dynamic_logged;

    /* Node A at slot 1 declares edges to slots 2 and 3: the
     * auto-ingest registers them. Slot 3 has no node yet —
     * registering an edge to an absent slot is fine (it is
     * populated later). */
    err = xgl_graph_add_node(g, 1, OBJ_A, "edge_node_a");
    if (err) {
        printf("FAIL: add node A: %d (%s)\n", err, strerror(-err));
        return 1;
    }

    /* Node B at slot 2 declares an edge back to slot 1: with A's
     * auto-ingested 1->2 edge this closes a cycle. add_node must
     * reject it and roll back. */
    err = xgl_graph_add_node(g, 2, OBJ_B, "edge_node_b");
    if (err != -ELOOP) {
        printf("FAIL: expected -ELOOP from code-declared cycle, got %d\n",
               err);
        return 1;
    }

    printf("PASS: code-declared cycle rejected at add_node\n");
    xgl_graph_destroy(g);
    return 0;
}
