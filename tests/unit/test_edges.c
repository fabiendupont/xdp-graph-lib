/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unit tests for the ".xgl.edges" metadata section (no privileges
 * required — pure ELF parsing).
 *
 * The test objects are compiled from tests/bpf/edge_node_{a,b}.bpf.c
 * with XGL_EDGE()/XGL_EDGE_DYNAMIC() declarations.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xgl/bpf/xgl_edges.bpf.h>
#include <xgl/xgl_graph.h>

#ifndef EDGE_OBJ_DIR
#define EDGE_OBJ_DIR "."
#endif

#define OBJ_A EDGE_OBJ_DIR "/edge_node_a.bpf.o"
#define OBJ_B EDGE_OBJ_DIR "/edge_node_b.bpf.o"

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

static void test_read_all(void)
{
    struct xgl_edge_meta *entries = NULL;
    size_t n = 0;

    /* Node A declares 3 entries: slots 2, 3 and the dynamic
     * sentinel. */
    CHECK(xgl_graph_read_all_edges(OBJ_A, &entries, &n) == 0);
    CHECK(n == 3);
    if (n == 3) {
        CHECK(strcmp(entries[0].prog, "edge_node_a") == 0);
        CHECK(entries[0].to == 2);
        CHECK(entries[1].to == 3);
        CHECK(entries[2].to == XGL_EDGE_DYNAMIC_SENTINEL);
    }
    free(entries);
}

static void test_read_filtered(void)
{
    uint32_t *targets = NULL;
    size_t n = 0;

    CHECK(xgl_graph_read_edges(OBJ_A, "edge_node_a", &targets, &n) == 0);
    CHECK(n == 3);
    if (n == 3)
        CHECK(targets[0] == 2 && targets[1] == 3 &&
              targets[2] == XGL_EDGE_DYNAMIC_SENTINEL);
    free(targets);

    /* Unknown program: entries exist but none match. */
    targets = (uint32_t *)0x1;
    CHECK(xgl_graph_read_edges(OBJ_A, "no_such_prog", &targets, &n)
          == -ENOENT);
    CHECK(targets == NULL);

    /* Node B declares a single edge back to slot 1. */
    CHECK(xgl_graph_read_edges(OBJ_B, "edge_node_b", &targets, &n) == 0);
    CHECK(n == 1);
    if (n == 1)
        CHECK(targets[0] == 1);
    free(targets);
}

static void test_missing_section(void)
{
    uint32_t *targets = NULL;
    size_t n = 0;

    /* Objects predating the macro declare no section. */
    CHECK(xgl_graph_read_all_edges(EDGE_OBJ_DIR "/xgl_dispatch.bpf.o",
                                   (struct xgl_edge_meta **)&targets,
                                   &n) == -ENOENT);
}

int main(void)
{
    test_read_all();
    test_read_filtered();
    test_missing_section();

    if (failures == 0) {
        printf("xgl_edges tests: all passed\n");
        return 0;
    }
    printf("xgl_edges tests: %d failure(s)\n", failures);
    return 1;
}
