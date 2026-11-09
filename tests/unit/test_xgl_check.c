/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unit tests for xgl_check — the deterministic graph-level static
 * check.  Each case builds a spec in memory and asserts the finding
 * codes.  Also asserts output determinism (same spec -> identical
 * findings, twice).
 */

#include <stdio.h>
#include <string.h>

#include "xgl/xgl_check.h"

static int failures = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static void spec_init(struct xgl_check_spec *s, int max_nodes, int root)
{
    memset(s, 0, sizeof(*s));
    (void)snprintf(s->name, sizeof(s->name), "test");
    s->max_nodes = max_nodes;
    s->root_index = root;
}

static void add_node(struct xgl_check_spec *s, int index, const char *name,
                     bool stateful)
{
    s->nodes[s->n_nodes].index = index;
    (void)snprintf(s->nodes[s->n_nodes].name,
                   sizeof(s->nodes[s->n_nodes].name), "%s", name);
    s->nodes[s->n_nodes].stateful = stateful;
    s->n_nodes++;
}

static void add_edge(struct xgl_check_spec *s, int from, int to)
{
    s->edges[s->n_edges].from = from;
    s->edges[s->n_edges].to = to;
    s->n_edges++;
}

static void add_xsk(struct xgl_check_spec *s, const char *ifname, int queue,
                    int n_queues, bool zerocopy,
                    int irq, int cpu, int numa, int cpu_numa)
{
    (void)snprintf(s->xsks[s->n_xsks].ifname,
                   sizeof(s->xsks[s->n_xsks].ifname), "%s", ifname);
    s->xsks[s->n_xsks].queue_id = queue;
    s->xsks[s->n_xsks].n_queues = n_queues;
    s->xsks[s->n_xsks].zerocopy = zerocopy;
    s->xsks[s->n_xsks].irq = irq;
    s->xsks[s->n_xsks].cpu = cpu;
    s->xsks[s->n_xsks].numa_node = numa;
    s->xsks[s->n_xsks].cpu_numa_node = cpu_numa;
    s->n_xsks++;
}

static void add_filter(struct xgl_check_spec *s, const char *ifname,
                       int queue, unsigned short etype)
{
    (void)snprintf(s->filters[s->n_filters].ifname,
                   sizeof(s->filters[s->n_filters].ifname), "%s", ifname);
    s->filters[s->n_filters].queue_id = queue;
    s->filters[s->n_filters].ethertype = etype;
    s->n_filters++;
}

static bool has_code(const struct xgl_check_finding *f, int n,
                     enum xgl_check_code code)
{
    int i;

    for (i = 0; i < n; i++)
        if (f[i].code == code)
            return true;
    return false;
}

static bool only_ok(const struct xgl_check_finding *f, int n)
{
    int i;

    for (i = 0; i < n; i++)
        if (f[i].severity == XGL_CHECK_SEV_ERROR)
            return false;
    return true;
}

/* A valid GOOSE/SV pipeline: root -> goose_filter -> sv_filter,
 * each filter redirecting to its own dedicated queue. */
static void test_valid(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[32];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "goose_filter", false);
    add_node(&s, 2, "sv_filter", false);
    add_edge(&s, 0, 1);
    add_edge(&s, 0, 2);
    add_xsk(&s, "eth0", 0, 8, true, 24, 2, 0, 0);
    add_xsk(&s, "eth0", 1, 8, true, 25, 3, 0, 0);
    add_filter(&s, "eth0", 0, 0x88B8);
    add_filter(&s, "eth0", 1, 0x88BA);

    n = xgl_check_validate(&s, f, 32);
    CHECK(n == 0);
    CHECK(only_ok(f, n));
}

static void test_null_spec(void)
{
    CHECK(xgl_check_validate(NULL, NULL, 0) == -1);
}

static void test_empty(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_NO_NODES));
}

static void test_root_missing(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 7);
    add_node(&s, 0, "dispatch", false);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_ROOT_MISSING));
}

static void test_dup_index(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "a", false);
    add_node(&s, 0, "b", false);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_INDEX_DUP));
}

static void test_index_range(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 4, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 9, "out_of_range", false);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_INDEX_RANGE));
}

static void test_cycle(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "a", false);
    add_node(&s, 2, "b", false);
    add_edge(&s, 0, 1);
    add_edge(&s, 1, 2);
    add_edge(&s, 2, 1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_CYCLE));
}

static void test_self_loop(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "loopy", false);
    add_edge(&s, 0, 1);
    add_edge(&s, 1, 1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_EDGE_SELF));
    CHECK(has_code(f, n, XGL_CHECK_E_CYCLE));
}

static void test_unreachable(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "orphan", false);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_UNREACHABLE));
}

static void test_edge_endpoint(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_edge(&s, 0, 5);     /* no node 5 */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_EDGE_ENDPOINT));
}

static void test_queue_range(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 12, 8, true, -1, -1, -1, -1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_QUEUE_RANGE));
}

static void test_queue_dup(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 3, 8, true, -1, -1, -1, -1);
    add_xsk(&s, "eth0", 3, 8, true, -1, -1, -1, -1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_QUEUE_DUP));
}

static void test_queue_dup_other_if(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    /* same queue id on different interfaces is fine */
    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 3, 8, true, -1, -1, -1, -1);
    add_xsk(&s, "eth1", 3, 4, true, -1, -1, -1, -1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(!has_code(f, n, XGL_CHECK_E_QUEUE_DUP));
}

static void test_filter_no_xsk(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_filter(&s, "eth0", 0, 0x88B8);   /* no xsk on eth0:0 */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_FILTER_NO_XSK));
}

static void test_etype_range(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    add_filter(&s, "eth0", 0, 0x0600 - 1);  /* 0x05FF: length field */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_ETYPE_RANGE));
}

static void test_filter_dup(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    add_filter(&s, "eth0", 0, 0x88B8);
    add_filter(&s, "eth0", 0, 0x88B8);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_FILTER_DUP));
}

static void test_filter_overlap(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    /* GOOSE on two queues of the same interface: ambiguous path */
    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    add_xsk(&s, "eth0", 1, 8, true, -1, -1, -1, -1);
    add_filter(&s, "eth0", 0, 0x88B8);
    add_filter(&s, "eth0", 1, 0x88B8);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_FILTER_OVERLAP));
}

static void test_filter_disjoint_ifs(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    /* same ethertype on different interfaces: fine */
    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    add_xsk(&s, "eth1", 0, 4, true, -1, -1, -1, -1);
    add_filter(&s, "eth0", 0, 0x88B8);
    add_filter(&s, "eth1", 0, 0x88B8);
    n = xgl_check_validate(&s, f, 8);
    CHECK(!has_code(f, n, XGL_CHECK_E_FILTER_OVERLAP));
}

static void test_warnings(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "hsr_dup_detect", true);   /* stateful */
    add_edge(&s, 0, 1);
    add_xsk(&s, "eth0", 0, 8, false, 30, -1, -1, -1);          /* copy mode */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_W_STATEFUL));
    CHECK(has_code(f, n, XGL_CHECK_W_NO_ZEROCOPY));
    CHECK(only_ok(f, n));                      /* no errors */
}

static void test_irq_dup(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, 24, 2, 0, 0);
    add_xsk(&s, "eth0", 1, 8, true, 24, 3, 0, 0);   /* same IRQ 24 */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_IRQ_DUP));
}

static void test_cpu_dup(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, 24, 2, 0, 0);
    add_xsk(&s, "eth1", 0, 4, true, 40, 2, 0, 0);   /* same CPU 2 */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_E_CPU_DUP));
}

static void test_numa_mismatch(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, 24, 2, 1, 0);   /* queue numa 1, cpu numa 0 */
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_W_NUMA_MISMATCH));
    CHECK(only_ok(f, n));
}

static void test_no_dedication(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding f[8];
    int n;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    n = xgl_check_validate(&s, f, 8);
    CHECK(has_code(f, n, XGL_CHECK_W_NO_DEDICATION));
    CHECK(only_ok(f, n));
}

static void test_determinism(void)
{
    struct xgl_check_spec s;
    struct xgl_check_finding a[16], b[16];
    int na, nb, i;

    spec_init(&s, 16, 0);
    add_node(&s, 0, "dispatch", false);
    add_node(&s, 1, "goose", false);
    add_node(&s, 2, "sv", false);
    add_node(&s, 3, "dup", true);
    add_edge(&s, 0, 1);
    add_edge(&s, 0, 2);
    add_edge(&s, 2, 3);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);
    add_xsk(&s, "eth0", 0, 8, true, -1, -1, -1, -1);           /* dup queue */
    add_filter(&s, "eth0", 0, 0x88B8);
    add_filter(&s, "eth0", 1, 0x88B8);         /* overlap */

    na = xgl_check_validate(&s, a, 16);
    nb = xgl_check_validate(&s, b, 16);
    CHECK(na == nb);
    for (i = 0; i < na; i++) {
        CHECK(a[i].code == b[i].code);
        CHECK(a[i].severity == b[i].severity);
        CHECK(strcmp(a[i].message, b[i].message) == 0);
    }
}

int main(void)
{
    test_valid();
    test_null_spec();
    test_empty();
    test_root_missing();
    test_dup_index();
    test_index_range();
    test_cycle();
    test_self_loop();
    test_unreachable();
    test_edge_endpoint();
    test_queue_range();
    test_queue_dup();
    test_queue_dup_other_if();
    test_filter_no_xsk();
    test_etype_range();
    test_filter_dup();
    test_filter_overlap();
    test_filter_disjoint_ifs();
    test_warnings();
    test_irq_dup();
    test_cpu_dup();
    test_numa_mismatch();
    test_no_dedication();
    test_determinism();

    if (failures == 0) {
        printf("xgl_check tests: all passed\n");
        return 0;
    }
    printf("xgl_check tests: %d failure(s)\n", failures);
    return 1;
}
