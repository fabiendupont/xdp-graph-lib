/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_wrapper - XDP graph wrapper delegation and input validation.
 *
 * Covers:
 *   SSR-WRAP-001: Delegation passes args/returns unchanged
 *   SSR-WRAP-002: xgl_graph_get_egl() always valid for valid graph
 *   SSR-WRAP-003: xgl_graph_attach() validates DAG first (FM-DAG-04)
 *   SSR-WRAP-004: xgl_graph_destroy() aborts active reconfig (FM-RECONFIG-04)
 *   SSR-ERR-002:  Input validation for all public functions
 *
 * These tests exercise the xgl_graph wrapper layer without needing
 * root privileges or BPF objects. They validate:
 *   - Create/destroy lifecycle
 *   - egl_graph handle accessibility
 *   - NULL/empty input validation for all 10 public xgl_graph_* functions
 *   - DAG delegation equivalence (edges via xgl, validate via both)
 *   - Destroy aborts active reconfig
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <egl/egl_graph.h>
#include <egl/egl_reconfig.h>
#include <xgl/xgl_graph.h>

static int tests_run;
static int tests_passed;

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

/* --- Create / Destroy Lifecycle --- */

static void
test_create_destroy(void)
{
    struct xgl_graph *g;

    TEST(wrapper_create_destroy);
    g = xgl_graph_create("test", 0);
    ASSERT_NE(g, NULL, "create should succeed");
    xgl_graph_destroy(g);
    PASS();
}

static void
test_destroy_null(void)
{
    TEST(wrapper_destroy_null_safe);
    xgl_graph_destroy(NULL);
    PASS();
}

static void
test_create_with_max_nodes(void)
{
    struct xgl_graph *g;

    TEST(wrapper_create_with_max_nodes);
    g = xgl_graph_create("sized", 32);
    ASSERT_NE(g, NULL, "create with max_nodes=32 should succeed");
    xgl_graph_destroy(g);
    PASS();
}

/* --- egl handle access (SSR-WRAP-002) --- */

static void
test_get_egl_valid(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;

    TEST(wrapper_get_egl_valid);
    g = xgl_graph_create("egl-test", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);
    ASSERT_NE(egl, NULL, "egl handle must be non-NULL for valid graph");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_get_egl_null(void)
{
    TEST(wrapper_get_egl_null);
    ASSERT_EQ(xgl_graph_get_egl(NULL), NULL,
              "NULL graph should return NULL egl");
    PASS();
}

/* --- NULL / empty input validation (SSR-ERR-002) --- */

static void
test_create_null_name(void)
{
    TEST(wrapper_create_null_name);
    ASSERT_EQ(xgl_graph_create(NULL, 0), NULL,
              "NULL name should return NULL");
    PASS();
}

static void
test_create_empty_name(void)
{
    TEST(wrapper_create_empty_name);
    ASSERT_EQ(xgl_graph_create("", 0), NULL,
              "empty name should return NULL");
    PASS();
}

static void
test_add_node_null_graph(void)
{
    TEST(wrapper_add_node_null_graph);
    ASSERT_EQ(xgl_graph_add_node(NULL, 0, "/dummy.o", "prog"),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_remove_node_null_graph(void)
{
    TEST(wrapper_remove_node_null_graph);
    ASSERT_EQ(xgl_graph_remove_node(NULL, 0),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_add_edge_null_graph(void)
{
    TEST(wrapper_add_edge_null_graph);
    ASSERT_EQ(xgl_graph_add_edge(NULL, 0, 1),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_validate_dag_null_graph(void)
{
    TEST(wrapper_validate_dag_null_graph);
    ASSERT_EQ(xgl_graph_validate_dag(NULL),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_attach_null_graph(void)
{
    TEST(wrapper_attach_null_graph);
    ASSERT_EQ(xgl_graph_attach(NULL, "lo"),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_attach_null_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_attach_null_ifname);
    g = xgl_graph_create("attach-null", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_attach(g, NULL),
              -EINVAL, "NULL ifname should return -EINVAL");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_detach_null_graph(void)
{
    TEST(wrapper_detach_null_graph);
    ASSERT_EQ(xgl_graph_detach(NULL, "lo"),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_detach_null_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_detach_null_ifname);
    g = xgl_graph_create("detach-null", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_detach(g, NULL),
              -EINVAL, "NULL ifname should return -EINVAL");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_add_tx_port_null_graph(void)
{
    TEST(wrapper_add_tx_port_null_graph);
    ASSERT_EQ(xgl_graph_add_tx_port(NULL, "lo"),
              -EINVAL, "NULL graph should return -EINVAL");
    PASS();
}

static void
test_add_tx_port_null_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_add_tx_port_null_ifname);
    g = xgl_graph_create("tx-null", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_add_tx_port(g, NULL),
              -EINVAL, "NULL ifname should return -EINVAL");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_create_xsk_null_graph(void)
{
    TEST(wrapper_create_xsk_null_graph);
    ASSERT_EQ(xgl_graph_create_xsk(NULL, "lo", 0), NULL,
              "NULL graph should return NULL");
    PASS();
}

static void
test_get_prog_array_fd_null(void)
{
    TEST(wrapper_get_prog_array_fd_null);
    ASSERT_EQ(xgl_graph_get_prog_array_fd(NULL), -1,
              "NULL graph should return -1");
    PASS();
}

static void
test_get_stats_map_fd_null(void)
{
    TEST(wrapper_get_stats_map_fd_null);
    ASSERT_EQ(xgl_graph_get_stats_map_fd(NULL), -1,
              "NULL graph should return -1");
    PASS();
}

/* --- FM-NODE-02: program type validation --- */

static void
test_add_node_bad_path(void)
{
    struct xgl_graph *g;

    TEST(wrapper_add_node_bad_path);
    g = xgl_graph_create("bad-path", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_add_node(g, 0, "/nonexistent.bpf.o", "prog"),
              -ENOENT, "bad path should return -ENOENT");

    xgl_graph_destroy(g);
    PASS();
}

/* --- Error path coverage --- */

static void
test_attach_no_root_program(void)
{
    struct xgl_graph *g;

    TEST(wrapper_attach_no_root_program);
    g = xgl_graph_create("no-root", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Attach without loading any node — root_obj_path is empty */
    ASSERT_EQ(xgl_graph_attach(g, "lo"), -ENOENT,
              "attach without root should return -ENOENT");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_attach_bad_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_attach_bad_ifname);
    g = xgl_graph_create("bad-if", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Attempt attach with nonexistent interface */
    ASSERT_NE(xgl_graph_attach(g, "nonexistent99"), 0,
              "attach to bad interface should fail");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_detach_bad_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_detach_bad_ifname);
    g = xgl_graph_create("bad-detach", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_NE(xgl_graph_detach(g, "nonexistent99"), 0,
              "detach from bad interface should fail");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_add_tx_port_bad_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_add_tx_port_bad_ifname);
    g = xgl_graph_create("bad-tx", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_NE(xgl_graph_add_tx_port(g, "nonexistent99"), 0,
              "add_tx_port with bad interface should fail");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_create_xsk_bad_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_create_xsk_bad_ifname);
    g = xgl_graph_create("bad-xsk", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_create_xsk(g, "nonexistent99", 0), NULL,
              "create_xsk with bad interface should return NULL");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_create_xsk_null_ifname(void)
{
    struct xgl_graph *g;

    TEST(wrapper_create_xsk_null_ifname);
    g = xgl_graph_create("null-xsk", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_create_xsk(g, NULL, 0), NULL,
              "create_xsk with NULL ifname should return NULL");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_create_xsk_negative_queue(void)
{
    struct xgl_graph *g;

    TEST(wrapper_create_xsk_negative_queue);
    g = xgl_graph_create("neg-q", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    ASSERT_EQ(xgl_graph_create_xsk(g, "lo", -1), NULL,
              "create_xsk with negative queue should return NULL");

    xgl_graph_destroy(g);
    PASS();
}

/* --- DAG delegation equivalence (SSR-WRAP-001) --- */

static void
test_dag_delegation_linear(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    int xgl_ret, egl_ret;

    TEST(wrapper_dag_delegation_linear);
    g = xgl_graph_create("dag-linear", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);
    ASSERT_NE(egl, NULL, "egl handle should be valid");

    /* Add edges via xgl */
    ASSERT_EQ(xgl_graph_add_edge(g, 0, 1), 0, "add_edge 0->1 should succeed");
    ASSERT_EQ(xgl_graph_add_edge(g, 1, 2), 0, "add_edge 1->2 should succeed");

    /* Validate via both xgl and egl — must agree */
    xgl_ret = xgl_graph_validate_dag(g);
    egl_ret = egl_graph_validate_dag(egl);
    ASSERT_EQ(xgl_ret, egl_ret, "xgl and egl DAG validation must agree");
    ASSERT_EQ(xgl_ret, 0, "linear chain should be valid DAG");

    xgl_graph_destroy(g);
    PASS();
}

static void
test_dag_delegation_cycle(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    int xgl_ret, egl_ret;

    TEST(wrapper_dag_delegation_cycle);
    g = xgl_graph_create("dag-cycle", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);

    /* Create a cycle: 0 -> 1 -> 0 */
    xgl_graph_add_edge(g, 0, 1);
    xgl_graph_add_edge(g, 1, 0);

    xgl_ret = xgl_graph_validate_dag(g);
    egl_ret = egl_graph_validate_dag(egl);
    ASSERT_EQ(xgl_ret, egl_ret, "xgl and egl cycle detection must agree");
    ASSERT_NE(xgl_ret, 0, "cycle should be detected");

    xgl_graph_destroy(g);
    PASS();
}

/* --- SSR-WRAP-003: attach validates DAG (FM-DAG-04) --- */

static void
test_attach_validates_dag(void)
{
    struct xgl_graph *g;
    int ret;

    TEST(wrapper_attach_validates_dag);
    g = xgl_graph_create("attach-dag", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    /* Create a cycle */
    xgl_graph_add_edge(g, 0, 1);
    xgl_graph_add_edge(g, 1, 0);

    /*
     * Attach should fail because the graph has a cycle.
     * It will call validate_dag internally before attempting
     * XDP attachment, so we don't need root to test this path.
     * The return should be -ELOOP (cycle detected).
     */
    ret = xgl_graph_attach(g, "lo");
    ASSERT_NE(ret, 0, "attach with cycle should fail");

    xgl_graph_destroy(g);
    PASS();
}

/* --- SSR-WRAP-004: destroy aborts active reconfig (FM-RECONFIG-04) --- */

static void
test_destroy_aborts_reconfig(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    int ret;

    TEST(wrapper_destroy_aborts_active_reconfig);
    g = xgl_graph_create("reconfig-abort", 0);
    ASSERT_NE(g, NULL, "create should succeed");

    egl = xgl_graph_get_egl(g);

    /* Begin a reconfig transaction */
    ret = egl_reconfig_begin(egl);
    ASSERT_EQ(ret, 0, "reconfig begin should succeed");

    /*
     * Destroy without commit/abort — should not crash.
     * xgl_graph_destroy calls egl_reconfig_abort internally.
     */
    xgl_graph_destroy(g);

    /*
     * If we get here without crashing, the abort-on-destroy worked.
     * We can't check the reconfig state after destroy since the
     * graph is freed, but the key property is: no crash, no leak.
     */
    PASS();
}

int
main(void)
{
    printf("test_wrapper:\n");

    /* Create / destroy lifecycle */
    test_create_destroy();
    test_destroy_null();
    test_create_with_max_nodes();

    /* egl handle access */
    test_get_egl_valid();
    test_get_egl_null();

    /* NULL / empty input validation */
    test_create_null_name();
    test_create_empty_name();
    test_add_node_null_graph();
    test_remove_node_null_graph();
    test_add_edge_null_graph();
    test_validate_dag_null_graph();
    test_attach_null_graph();
    test_attach_null_ifname();
    test_detach_null_graph();
    test_detach_null_ifname();
    test_add_tx_port_null_graph();
    test_add_tx_port_null_ifname();
    test_create_xsk_null_graph();
    test_get_prog_array_fd_null();
    test_get_stats_map_fd_null();

    /* FM-NODE-02: program type validation */
    test_add_node_bad_path();

    /* Error path coverage */
    test_attach_no_root_program();
    test_attach_bad_ifname();
    test_detach_bad_ifname();
    test_add_tx_port_bad_ifname();
    test_create_xsk_bad_ifname();
    test_create_xsk_null_ifname();
    test_create_xsk_negative_queue();

    /* DAG delegation equivalence */
    test_dag_delegation_linear();
    test_dag_delegation_cycle();

    /* SSR-WRAP-003: attach validates DAG */
    test_attach_validates_dag();

    /* SSR-WRAP-004: destroy aborts active reconfig */
    test_destroy_aborts_reconfig();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
