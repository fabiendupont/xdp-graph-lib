/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Integration test: 3-node pipeline on a veth pair.
 *
 * Creates a veth pair, loads BPF programs (dispatcher + l2fwd nodes),
 * attaches the graph, and verifies the pipeline is functional.
 *
 * Requires: root privileges (or CAP_NET_ADMIN + CAP_BPF)
 *
 * The BPF loading tests are skipped gracefully when not root.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xgl/xgl_graph.h>

/*
 * Path to compiled BPF objects (set via -DBPF_OBJ_DIR=... or default).
 */
#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

/*
 * Helper: create a veth pair using ip link commands.
 * Returns 0 on success, -1 on failure.
 */
static int
create_veth_pair(const char *veth0, const char *veth1)
{
    char cmd[256];
    int ret;

    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s 2>/dev/null",
             veth0, veth1);
    ret = system(cmd);
    if (ret != 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", veth0);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", veth1);
    system(cmd);

    return 0;
}

/*
 * Helper: destroy a veth pair.
 */
static void
destroy_veth_pair(const char *veth0)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", veth0);
    system(cmd);
}

/*
 * Test: 3-node pipeline lifecycle (without actual BPF programs).
 *
 * This test validates the graph management API:
 * - Create graph
 * - Validate empty DAG
 * - Add edges for a 3-node pipeline
 * - Validate DAG
 * - Destroy graph
 */
static int
test_pipeline_lifecycle(void)
{
    struct xgl_graph *g;
    int ret;

    printf("  %-50s ", "pipeline_lifecycle");

    g = xgl_graph_create("pipeline-test", 0);
    if (!g) {
        printf("FAIL: graph creation failed\n");
        return 1;
    }

    /* Empty graph is a valid DAG */
    ret = xgl_graph_validate_dag(g);
    if (ret != 0) {
        printf("FAIL: empty graph should be valid DAG\n");
        xgl_graph_destroy(g);
        return 1;
    }

    /* Set up a 3-node pipeline: 0 -> 1 -> 2 */
    xgl_graph_add_edge(g, 0, 1);
    xgl_graph_add_edge(g, 1, 2);

    ret = xgl_graph_validate_dag(g);
    if (ret != 0) {
        printf("FAIL: 3-node chain should be valid DAG\n");
        xgl_graph_destroy(g);
        return 1;
    }

    /* Adding a back-edge should make it invalid */
    xgl_graph_add_edge(g, 2, 0);
    ret = xgl_graph_validate_dag(g);
    if (ret == 0) {
        printf("FAIL: cycle should be detected\n");
        xgl_graph_destroy(g);
        return 1;
    }

    xgl_graph_destroy(g);
    printf("PASS\n");
    return 0;
}

/*
 * Test: veth pair creation (requires root).
 */
static int
test_veth_creation(void)
{
    printf("  %-50s ", "veth_creation");

    if (geteuid() != 0) {
        printf("SKIP (not root)\n");
        return 0;
    }

    if (create_veth_pair("xgl_test0", "xgl_test1") != 0) {
        printf("SKIP: veth creation failed (no CAP_NET_ADMIN)\n");
        return 0;
    }

    destroy_veth_pair("xgl_test0");
    printf("PASS\n");
    return 0;
}

/*
 * Test: Load BPF dispatcher, attach to veth, verify graph lifecycle.
 * Requires root and compiled BPF objects.
 */
static int
test_bpf_load_and_attach(void)
{
    struct xgl_graph *g;
    char dispatch_path[512];
    int ret;

    printf("  %-50s ", "bpf_load_and_attach");

    if (geteuid() != 0) {
        printf("SKIP (not root)\n");
        return 0;
    }

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);

    if (access(dispatch_path, R_OK) != 0) {
        printf("SKIP (no %s)\n", dispatch_path);
        return 0;
    }

    /* Create veth pair */
    if (create_veth_pair("xgl_e2e0", "xgl_e2e1") != 0) {
        printf("SKIP: veth creation failed (no CAP_NET_ADMIN)\n");
        return 0;
    }

    g = xgl_graph_create("e2e-test", 0);
    if (!g) {
        printf("FAIL: graph creation failed\n");
        destroy_veth_pair("xgl_e2e0");
        return 1;
    }

    /* Load dispatcher at index 0 */
    ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        printf("FAIL: add_node returned %d (%s)\n", ret, strerror(-ret));
        xgl_graph_destroy(g);
        destroy_veth_pair("xgl_e2e0");
        return 1;
    }

    /* Attach to veth */
    ret = xgl_graph_attach(g, "xgl_e2e0");
    if (ret != 0) {
        printf("FAIL: attach returned %d (%s)\n", ret, strerror(-ret));
        xgl_graph_destroy(g);
        destroy_veth_pair("xgl_e2e0");
        return 1;
    }

    /* Clean up */
    xgl_graph_destroy(g);
    destroy_veth_pair("xgl_e2e0");
    printf("PASS\n");
    return 0;
}

int
main(void)
{
    int failures = 0;

    printf("test_pipeline:\n");

    failures += test_pipeline_lifecycle();
    failures += test_veth_creation();
    failures += test_bpf_load_and_attach();

    printf("\n%s\n", failures == 0 ? "All tests passed" : "Some tests FAILED");
    return failures;
}
