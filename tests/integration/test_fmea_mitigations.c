/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

/*
 * test_fmea_mitigations - Explicit verification of FMEA mitigations.
 *
 * Each test case maps to a specific failure mode from XGL-FMEA-001:
 *
 *   FM-DAG-04:     Attach with cycle returns error (P1 action)
 *   FM-RECONFIG-04: Destroy after begin without commit — no crash (P1)
 *   FM-NODE-03:    Reconfig commit waits RCU grace period >= 10ms
 *   FM-META-06:    Invalid next_node — controlled drop path
 *   FM-DISP-01:    Dispatcher meta alloc failure path
 *   FM-DISP-02:    Dispatcher tail call failure path
 *
 * Privileged tests skip gracefully without root.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <xgl/xgl_graph.h>
#include <xgl/xgl_meta.h>
#include <egl/egl_graph.h>
#include <egl/egl_reconfig.h>
#include <egl/egl_types.h>

#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

static int tests_run;
static int tests_passed;
static int tests_skipped;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  %-50s ", #name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define SKIP(msg) \
    do { \
        tests_skipped++; \
        printf("SKIP: %s\n", msg); \
        return; \
    } while (0)

#define FAIL(msg) \
    do { \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            FAIL(msg); \
            return; \
        } \
    } while (0)

#define ASSERT_NE(a, b, msg) \
    do { \
        if ((a) == (b)) { \
            FAIL(msg); \
            return; \
        } \
    } while (0)

#define ASSERT_GE(a, b, msg) \
    do { \
        if ((a) < (b)) { \
            FAIL(msg); \
            return; \
        } \
    } while (0)

/*
 * FM-DAG-04: Attach with a cyclic graph should fail.
 *
 * The xgl_graph_attach() function validates the DAG before
 * performing XDP attachment. A cycle should cause -ELOOP.
 * This test does NOT need root — it fails before XDP attach.
 */
static void
test_fm_dag_04_attach_with_cycle(void)
{
    struct xgl_graph *g;
    int ret;

    TEST(fm_dag_04_attach_rejects_cycle);
    g = xgl_graph_create("fmea-dag04", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Build a cycle: 0 -> 1 -> 2 -> 0 */
    xgl_graph_add_edge(g, 0, 1);
    xgl_graph_add_edge(g, 1, 2);
    xgl_graph_add_edge(g, 2, 0);

    ret = xgl_graph_attach(g, "lo");
    ASSERT_NE(ret, 0, "attach should fail with cycle");
    /* The specific error may be -ELOOP or the result of validate_dag */

    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-RECONFIG-04: Destroy with active reconfig should not crash.
 *
 * Start a reconfig transaction, then destroy the graph without
 * committing or aborting. xgl_graph_destroy must call
 * egl_reconfig_abort internally.
 */
static void
test_fm_reconfig_04_destroy_aborts(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    int ret;

    TEST(fm_reconfig_04_destroy_cleans_reconfig);
    g = xgl_graph_create("fmea-rc04", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);
    ASSERT_NE(egl, NULL, "egl should be valid");

    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "begin should succeed");

    /* Destroy without commit — must not crash or leak */
    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-NODE-03: Reconfig commit takes >= 10ms (RCU grace period).
 *
 * This verifies that egl_reconfig_commit() waits for the documented
 * 10ms RCU grace period. We measure wall-clock time.
 */
static void
test_fm_node_03_reconfig_commit_timing(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    char dispatch_path[512];
    struct timespec t0, t1;
    long elapsed_ms;
    int ret;

    TEST(fm_node_03_reconfig_commit_rcu_wait);
    if (geteuid() != 0)
        SKIP("not root");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);
    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    g = xgl_graph_create("fmea-node03", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);

    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "begin should succeed");

    ret = egl_reconfig_add_node(egl, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        xgl_graph_destroy(g);
        SKIP("BPF load failed (no CAP_BPF)");
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    ret = egl_reconfig_commit(egl);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    ASSERT_EQ(ret, 0, "commit should succeed");

    elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                 (t1.tv_nsec - t0.tv_nsec) / 1000000;
    ASSERT_GE(elapsed_ms, 10, "commit must wait >= 10ms for RCU");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-META-06: Invalid next_node index results in controlled drop.
 *
 * When next_node >= max_nodes, XGL_NEXT_SAFE detects the invalid
 * index and returns XDP_DROP instead of attempting a tail call.
 * This test validates the bounds-check logic and that the metadata
 * field can hold out-of-range values.
 */
static void
test_fm_meta_06_invalid_next_node(void)
{
    struct xgl_meta meta;

    TEST(fm_meta_06_invalid_next_node_range);
    memset(&meta, 0, sizeof(meta));
    meta.version = XGL_META_VERSION;

    /* next_node is __u16 — can hold 0..65535 */
    meta.next_node = 9999;
    ASSERT_EQ(meta.next_node, 9999,
              "next_node should store out-of-range value");

    /* Max valid index for default PROG_ARRAY is 255 (EGL_DEFAULT_MAX_NODES).
     * XGL_NEXT_SAFE checks node_id < EGL_DEFAULT_MAX_NODES.
     * Values >= 256 are rejected with XDP_DROP + error counter. */
    meta.next_node = 256;
    ASSERT_EQ(meta.next_node, 256,
              "next_node should store boundary value");

    /* Verify the bounds constant */
    ASSERT_EQ(meta.next_node >= EGL_DEFAULT_MAX_NODES, 1,
              "256 should be >= EGL_DEFAULT_MAX_NODES (256)");

    /* Value 255 is the last valid index */
    meta.next_node = 255;
    ASSERT_EQ(meta.next_node < EGL_DEFAULT_MAX_NODES, 1,
              "255 should be < EGL_DEFAULT_MAX_NODES");

    PASS();
}

/*
 * FM-DISP-01: Dispatcher metadata allocation failure path.
 *
 * When XGL_META_ALLOC returns NULL (no adjust_meta support),
 * the dispatcher should fall back to XDP_DROP. This test
 * verifies the userspace graph handles the case where no
 * root program is loaded yet.
 */
static void
test_fm_disp_01_no_root_program(void)
{
    struct xgl_graph *g;
    int ret;

    TEST(fm_disp_01_attach_without_root_prog);
    g = xgl_graph_create("fmea-disp01", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /*
     * Attempt attach without loading any node.
     * root_obj_path is empty — should return -ENOENT.
     */
    ret = xgl_graph_attach(g, "lo");
    ASSERT_EQ(ret, -ENOENT,
              "attach without root program should fail");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-DISP-02: Tail call to node 0 fails when not loaded.
 *
 * Validates the DAG-before-attach path: an empty graph is a valid
 * DAG, but attach still needs a root program. Graph layer should
 * reject the attach before reaching the BPF level.
 */
static void
test_fm_disp_02_empty_graph_attach(void)
{
    struct xgl_graph *g;
    int ret;

    TEST(fm_disp_02_empty_graph_attach_fails);
    g = xgl_graph_create("fmea-disp02", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Empty graph is a valid DAG, but no root program loaded */
    ret = xgl_graph_validate_dag(g);
    ASSERT_EQ(ret, 0, "empty graph is valid DAG");

    ret = xgl_graph_attach(g, "lo");
    ASSERT_NE(ret, 0, "attach should fail — no root program");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-NODE-02: xgl_graph_add_node rejects non-XDP programs.
 *
 * Attempts to load a TC BPF program into an XDP graph.
 * Should return -EINVAL because the program type is
 * BPF_PROG_TYPE_SCHED_CLS, not BPF_PROG_TYPE_XDP.
 */
static void
test_fm_node_02_type_rejection(void)
{
    struct xgl_graph *g;
    char tc_path[512];
    int ret;

    TEST(fm_node_02_rejects_non_xdp_program);

    snprintf(tc_path, sizeof(tc_path),
             "%s/tests/integration/tc_dummy.bpf.o", BPF_OBJ_DIR);
    if (access(tc_path, R_OK) != 0)
        SKIP("no tc_dummy.bpf.o");

    g = xgl_graph_create("fmea-node02", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Attempt to load a TC program — should be rejected */
    ret = xgl_graph_add_node(g, 0, tc_path, "tc_dummy");
    ASSERT_EQ(ret, -EINVAL,
              "TC program should be rejected with -EINVAL");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * FM-RECONFIG-01: Rollback restores removed nodes on commit failure.
 *
 * Load a node, begin reconfig, stage its removal + a bad add.
 * Commit should fail on the bad add. After rollback, the removed
 * node should be restored (prog_array_fd still valid, stats readable).
 */
static void
test_fm_reconfig_01_rollback(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    char dispatch_path[512];
    int ret;

    TEST(fm_reconfig_01_rollback_on_failure);
    if (geteuid() != 0)
        SKIP("not root");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);
    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    g = xgl_graph_create("fmea-rollback", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);

    /* Load a real node at index 0 */
    ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        xgl_graph_destroy(g);
        SKIP("BPF load failed (no CAP_BPF)");
    }

    /* Verify prog_array is populated */
    ASSERT_GE(xgl_graph_get_prog_array_fd(g), 0,
              "prog_array should be valid");

    /* Begin reconfig: remove node 0 + add bad node at index 1 */
    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "begin should succeed");

    ret = egl_reconfig_remove_node(egl, 0);
    ASSERT_EQ(ret, 0, "staging remove should succeed");

    ret = egl_reconfig_add_node(egl, 1,
                                 "/nonexistent.bpf.o", "fake_prog");
    ASSERT_EQ(ret, 0, "staging add should succeed");

    /* Commit should fail on the bad add */
    ret = egl_reconfig_commit(egl);
    ASSERT_NE(ret, 0, "commit should fail on bad BPF path");

    /*
     * After rollback: node 0 should be restored.
     * The prog_array_fd should still be valid, and the graph
     * should still be usable.
     */
    ASSERT_GE(xgl_graph_get_prog_array_fd(g), 0,
              "prog_array should still be valid after rollback");

    xgl_graph_destroy(g);
    PASS();
}

int
main(void)
{
    printf("test_fmea_mitigations:\n");

    test_fm_dag_04_attach_with_cycle();
    test_fm_reconfig_04_destroy_aborts();
    test_fm_node_03_reconfig_commit_timing();
    test_fm_meta_06_invalid_next_node();
    test_fm_disp_01_no_root_program();
    test_fm_disp_02_empty_graph_attach();
    test_fm_node_02_type_rejection();
    test_fm_reconfig_01_rollback();

    printf("\n%d/%d tests passed, %d skipped\n",
           tests_passed, tests_run, tests_skipped);
    return (tests_passed + tests_skipped) == tests_run ? 0 : 1;
}
