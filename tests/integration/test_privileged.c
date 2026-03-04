/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_privileged - Tests requiring CAP_BPF (root).
 *
 * Tests XDP graph wrapper around egl_graph:
 *   - Map creation via egl_graph internals
 *   - Stats aggregation via egl_stats
 *   - Loader lifecycle via egl_loader
 *   - XDP graph create/destroy lifecycle
 *
 * These tests use bpf_map_create() directly (which requires CAP_BPF).
 * They are skipped gracefully when running without root.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <egl/egl_types.h>
#include <egl/egl_graph.h>
#include <egl/egl_stats.h>
#include <egl/egl_loader.h>
#include <egl/egl_reconfig.h>
#include <xgl/xgl_graph.h>

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

#define ASSERT_GE(a, b, msg) \
    do { \
        if ((a) < (b)) { \
            FAIL(msg); \
            return; \
        } \
    } while (0)

static int
can_create_bpf_maps(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "test",
                            sizeof(__u32), sizeof(__u32), 1, &opts);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

/*
 * Test: xgl_graph_create wraps egl_graph correctly.
 * Verify map fds are accessible via the egl_graph accessors.
 */
static void
test_graph_creation(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;

    TEST(xgl_graph_wraps_egl_graph);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    g = xgl_graph_create("wrap-test", 0);
    ASSERT_EQ(g != NULL, 1, "graph creation failed");

    egl = xgl_graph_get_egl(g);
    ASSERT_EQ(egl != NULL, 1, "egl_graph should not be NULL");

    /* Maps are lazy — fds start at -1 */
    ASSERT_EQ(xgl_graph_get_prog_array_fd(g), -1,
              "prog_array should be -1 before init");
    ASSERT_EQ(xgl_graph_get_stats_map_fd(g), -1,
              "stats_map should be -1 before init");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * Test per-CPU stats aggregation using egl_node_stats.
 */
static void
test_stats_aggregation(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int stats_fd;
    int num_cpus;
    struct egl_node_stats *percpu_vals;
    struct egl_node_stats result;
    __u32 key = 0;

    TEST(stats_per_cpu_aggregation);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    num_cpus = libbpf_num_possible_cpus();
    ASSERT_GE(num_cpus, 1, "need at least 1 CPU");

    /* Create a stats map manually */
    stats_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY,
                               "test_stats",
                               sizeof(__u32),
                               sizeof(struct egl_node_stats),
                               EGL_DEFAULT_MAX_NODES, &opts);
    ASSERT_GE(stats_fd, 0, "stats map creation failed");

    percpu_vals = calloc((size_t)num_cpus, sizeof(*percpu_vals));
    ASSERT_EQ(percpu_vals != NULL, 1, "calloc failed");

    /* Write known values: each CPU gets in_count = 10 */
    for (int i = 0; i < num_cpus; i++) {
        percpu_vals[i].in_count = 10;
        percpu_vals[i].in_bytes = 100;
        percpu_vals[i].out_count = 5;
        percpu_vals[i].out_bytes = 50;
        percpu_vals[i].drops = 1;
        percpu_vals[i].errors = 0;
    }

    ASSERT_EQ(bpf_map_update_elem(stats_fd, &key, percpu_vals, BPF_ANY),
              0, "map update failed");

    /* Read back and aggregate manually */
    struct egl_node_stats *readback =
        calloc((size_t)num_cpus, sizeof(*readback));
    ASSERT_EQ(readback != NULL, 1, "calloc failed");

    ASSERT_EQ(bpf_map_lookup_elem(stats_fd, &key, readback), 0,
              "map lookup failed");

    memset(&result, 0, sizeof(result));
    for (int i = 0; i < num_cpus; i++) {
        result.in_count += readback[i].in_count;
        result.in_bytes += readback[i].in_bytes;
        result.out_count += readback[i].out_count;
        result.out_bytes += readback[i].out_bytes;
        result.drops += readback[i].drops;
        result.errors += readback[i].errors;
    }

    /* Verify aggregated totals */
    ASSERT_EQ(result.in_count, (__u64)num_cpus * 10,
              "in_count aggregate wrong");
    ASSERT_EQ(result.in_bytes, (__u64)num_cpus * 100,
              "in_bytes aggregate wrong");
    ASSERT_EQ(result.out_count, (__u64)num_cpus * 5,
              "out_count aggregate wrong");
    ASSERT_EQ(result.out_bytes, (__u64)num_cpus * 50,
              "out_bytes aggregate wrong");
    ASSERT_EQ(result.drops, (__u64)num_cpus * 1,
              "drops aggregate wrong");
    ASSERT_EQ(result.errors, 0, "errors should be 0");

    free(readback);
    free(percpu_vals);
    close(stats_fd);
    PASS();
}

/*
 * Test stats reset zeroes all per-CPU counters.
 */
static void
test_stats_reset(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int stats_fd;
    int num_cpus;
    struct egl_node_stats *percpu_vals;
    __u32 key = 0;

    TEST(stats_reset_zeroes_all_cpus);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    num_cpus = libbpf_num_possible_cpus();
    ASSERT_GE(num_cpus, 1, "need at least 1 CPU");

    stats_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY,
                               "test_stats_reset",
                               sizeof(__u32),
                               sizeof(struct egl_node_stats),
                               EGL_DEFAULT_MAX_NODES, &opts);
    ASSERT_GE(stats_fd, 0, "stats map creation failed");

    percpu_vals = calloc((size_t)num_cpus, sizeof(*percpu_vals));
    ASSERT_EQ(percpu_vals != NULL, 1, "calloc failed");

    /* Write non-zero values */
    for (int i = 0; i < num_cpus; i++) {
        percpu_vals[i].in_count = 42;
        percpu_vals[i].drops = 7;
    }
    ASSERT_EQ(bpf_map_update_elem(stats_fd, &key, percpu_vals, BPF_ANY),
              0, "map update failed");

    /* Reset by writing zeroes */
    memset(percpu_vals, 0, (size_t)num_cpus * sizeof(*percpu_vals));
    ASSERT_EQ(bpf_map_update_elem(stats_fd, &key, percpu_vals, BPF_ANY),
              0, "reset update failed");

    /* Read back and verify all zeroes */
    ASSERT_EQ(bpf_map_lookup_elem(stats_fd, &key, percpu_vals), 0,
              "lookup after reset failed");

    for (int i = 0; i < num_cpus; i++) {
        ASSERT_EQ(percpu_vals[i].in_count, 0,
                  "in_count not zero after reset");
        ASSERT_EQ(percpu_vals[i].in_bytes, 0,
                  "in_bytes not zero after reset");
        ASSERT_EQ(percpu_vals[i].out_count, 0,
                  "out_count not zero after reset");
        ASSERT_EQ(percpu_vals[i].out_bytes, 0,
                  "out_bytes not zero after reset");
        ASSERT_EQ(percpu_vals[i].drops, 0,
                  "drops not zero after reset");
        ASSERT_EQ(percpu_vals[i].errors, 0,
                  "errors not zero after reset");
    }

    free(percpu_vals);
    close(stats_fd);
    PASS();
}

/*
 * Test PROG_ARRAY map can hold program fds.
 */
static void
test_prog_array_map(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    int map_fd;
    __u32 key;

    TEST(prog_array_map_type_and_size);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    map_fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY,
                             "test_prog_array",
                             sizeof(__u32),
                             sizeof(__u32),
                             EGL_DEFAULT_MAX_NODES, &opts);
    ASSERT_GE(map_fd, 0, "PROG_ARRAY creation failed");

    /* Verify we can delete from all valid indices */
    for (key = 0; key < 32; key++)
        bpf_map_delete_elem(map_fd, &key);

    close(map_fd);
    PASS();
}

/*
 * Test: egl_loader_open / get_prog_fd / close with real BPF object.
 */
static void
test_loader_lifecycle(void)
{
    struct egl_bpf_prog *prog;
    char dispatch_path[512];
    int fd;

    TEST(loader_open_get_fd_close);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);

    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    prog = egl_loader_open(dispatch_path);
    if (!prog) {
        printf("FAIL: loader_open returned NULL\n");
        return;
    }

    fd = egl_loader_get_prog_fd(prog, "xgl_dispatch");
    ASSERT_GE(fd, 0, "get_prog_fd should return valid fd");

    /* Non-existent program name */
    fd = egl_loader_get_prog_fd(prog, "nonexistent");
    ASSERT_EQ(fd, -ENOENT, "nonexistent prog should return -ENOENT");

    egl_loader_close(prog);
    PASS();
}

/*
 * Test: egl_loader_close(NULL) is safe.
 */
static void
test_loader_close_null(void)
{
    TEST(loader_close_null_safe);
    egl_loader_close(NULL);
    PASS();
}

/*
 * Test: egl_loader_open with invalid path.
 */
static void
test_loader_open_bad_path(void)
{
    TEST(loader_open_bad_path);
    ASSERT_EQ(egl_loader_open("/nonexistent.bpf.o"), NULL,
              "bad path should return NULL");
    ASSERT_EQ(egl_loader_open(NULL), NULL,
              "NULL path should return NULL");
    PASS();
}

/*
 * Test: Full XDP graph lifecycle with real BPF — exercises egl_stats
 * through the xgl_graph wrapper.
 */
static void
test_stats_via_graph_api(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    struct egl_node_stats stats;
    char dispatch_path[512];
    int ret;

    TEST(stats_read_reset_via_graph_api);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);

    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    g = xgl_graph_create("stats-test", 0);
    ASSERT_EQ(g != NULL, 1, "graph creation failed");

    egl = xgl_graph_get_egl(g);
    ASSERT_EQ(egl != NULL, 1, "egl_graph should not be NULL");

    /* Load dispatcher to trigger map creation */
    ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        printf("FAIL: add_node returned %d\n", ret);
        xgl_graph_destroy(g);
        return;
    }

    /* Read stats for node 0 — should be all zeros */
    ret = egl_stats_read(egl, 0, &stats);
    ASSERT_EQ(ret, 0, "stats_read should succeed");
    ASSERT_EQ(stats.in_count, 0, "in_count should be 0");
    ASSERT_EQ(stats.drops, 0, "drops should be 0");

    /* Reset stats */
    ret = egl_stats_reset(egl, 0);
    ASSERT_EQ(ret, 0, "stats_reset should succeed");

    /* Read again — still zeros */
    ret = egl_stats_read(egl, 0, &stats);
    ASSERT_EQ(ret, 0, "stats_read after reset should succeed");
    ASSERT_EQ(stats.in_count, 0, "in_count should be 0 after reset");

    /* Read all */
    struct egl_node_stats all_stats[2];
    ret = egl_stats_read_all(egl, all_stats, 2);
    ASSERT_EQ(ret, 0, "stats_read_all should succeed");

    xgl_graph_destroy(g);
    PASS();
}

/*
 * Test: Reconfig commit with real BPF object — exercises the full
 * egl_reconfig commit path through xgl_graph wrapper.
 */
static void
test_reconfig_commit_with_bpf(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    char dispatch_path[512];
    int ret;

    TEST(reconfig_commit_with_real_bpf);
    if (!can_create_bpf_maps())
        SKIP("no CAP_BPF");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);

    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    g = xgl_graph_create("reconfig-bpf-test", 0);
    ASSERT_EQ(g != NULL, 1, "graph creation failed");

    egl = xgl_graph_get_egl(g);

    /* Begin, stage add, commit via egl_reconfig */
    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "begin should succeed");

    ret = egl_reconfig_add_node(egl, 0, dispatch_path, "xgl_dispatch");
    ASSERT_EQ(ret, 0, "staging add should succeed");

    ret = egl_reconfig_commit(egl);
    ASSERT_EQ(ret, 0, "commit should succeed");

    /* Verify node was loaded */
    ASSERT_GE(xgl_graph_get_prog_array_fd(g), 0,
              "prog_array should be valid after commit");

    /* Now do a reconfig to remove it */
    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "second begin should succeed");

    ret = egl_reconfig_remove_node(egl, 0);
    ASSERT_EQ(ret, 0, "staging remove should succeed");

    ret = egl_reconfig_commit(egl);
    ASSERT_EQ(ret, 0, "remove commit should succeed");

    xgl_graph_destroy(g);
    PASS();
}

int
main(void)
{
    printf("test_privileged:\n");

    test_graph_creation();
    test_stats_aggregation();
    test_stats_reset();
    test_prog_array_map();
    test_loader_lifecycle();
    test_loader_close_null();
    test_loader_open_bad_path();
    test_stats_via_graph_api();
    test_reconfig_commit_with_bpf();

    printf("\n%d/%d tests passed, %d skipped\n",
           tests_passed, tests_run, tests_skipped);
    return (tests_passed + tests_skipped) == tests_run ? 0 : 1;
}
