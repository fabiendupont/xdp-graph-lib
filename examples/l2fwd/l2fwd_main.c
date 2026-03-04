/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * l2fwd_main - Userspace driver for the L2 forwarder example.
 *
 * Usage: l2fwd <interface> [rx.bpf.o] [tx.bpf.o]
 *
 * Creates a 2-node graph (rx -> tx), attaches to the specified
 * interface, and prints per-node statistics every second.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <egl/egl_graph.h>
#include <egl/egl_stats.h>
#include <egl/egl_types.h>
#include <xgl/xgl_graph.h>

static volatile int running = 1;

static void
sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void
print_stats(struct xgl_graph *g)
{
    struct egl_graph *egl = xgl_graph_get_egl(g);
    struct egl_node_stats stats;

    printf("%-8s %12s %12s %12s %12s %8s %8s\n",
           "Node", "RX pkts", "RX bytes", "TX pkts", "TX bytes",
           "Drops", "Errors");

    for (int i = 0; i < 2; i++) {
        if (egl_stats_read(egl, i, &stats) == 0) {
            printf("%-8d %12llu %12llu %12llu %12llu %8llu %8llu\n",
                   i,
                   (unsigned long long)stats.in_count,
                   (unsigned long long)stats.in_bytes,
                   (unsigned long long)stats.out_count,
                   (unsigned long long)stats.out_bytes,
                   (unsigned long long)stats.drops,
                   (unsigned long long)stats.errors);
        }
    }
    printf("\n");
}

int
main(int argc, char **argv)
{
    struct xgl_graph *g;
    const char *ifname;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [rx.bpf.o] [tx.bpf.o]\n",
                argv[0]);
        return 1;
    }

    ifname = argv[1];
    const char *rx_obj = argc > 2 ? argv[2] : "l2fwd_rx.bpf.o";
    const char *tx_obj = argc > 3 ? argv[3] : "l2fwd_tx.bpf.o";

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    g = xgl_graph_create("l2fwd", 0);
    if (!g) {
        fprintf(stderr, "Failed to create graph: %s\n", strerror(errno));
        return 1;
    }

    /* Add RX node at index 0 (root) */
    err = xgl_graph_add_node(g, 0, rx_obj, "l2fwd_rx");
    if (err) {
        fprintf(stderr, "Failed to add RX node: %s\n", strerror(-err));
        xgl_graph_destroy(g);
        return 1;
    }

    /* Add TX node at index 1 */
    err = xgl_graph_add_node(g, 1, tx_obj, "l2fwd_tx");
    if (err) {
        fprintf(stderr, "Failed to add TX node: %s\n", strerror(-err));
        xgl_graph_destroy(g);
        return 1;
    }

    /* Declare edges for DAG validation */
    xgl_graph_add_edge(g, 0, 1);

    err = xgl_graph_validate_dag(g);
    if (err) {
        fprintf(stderr, "Graph is not a valid DAG\n");
        xgl_graph_destroy(g);
        return 1;
    }

    /* Attach to interface */
    err = xgl_graph_attach(g, ifname);
    if (err) {
        fprintf(stderr, "Failed to attach to %s: %s\n",
                ifname, strerror(-err));
        xgl_graph_destroy(g);
        return 1;
    }

    printf("L2 forwarder attached to %s. Press Ctrl-C to stop.\n\n",
           ifname);

    /* Print stats loop */
    while (running) {
        print_stats(g);
        sleep(1);
    }

    printf("\nDetaching and cleaning up...\n");
    xgl_graph_destroy(g);
    return 0;
}
