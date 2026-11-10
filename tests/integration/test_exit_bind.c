/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Privileged integration test for named exits: bind -> add_node ->
 * attach on a veth -> inject a frame -> observe the bound node's
 * stats, proving the patched tail call reached the bound slot.
 *
 * Also verifies add_node fails with -ENOENT on an unbound exit.
 * Skips without CAP_BPF (CI).
 */

#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <egl/egl_graph.h>
#include <egl/egl_stats.h>
#include <egl/egl_types.h>
#include <xgl/xgl_graph.h>

#ifndef EXIT_OBJ_DIR
#define EXIT_OBJ_DIR "."
#endif

#define OBJ_A EXIT_OBJ_DIR "/exit_node_a.bpf.o"
#define OBJ_B EXIT_OBJ_DIR "/exit_node_b.bpf.o"

static int have_bpf(void)
{
    int fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "probe",
                            sizeof(__u32), sizeof(__u32), 1, NULL);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int inject(const char *ifname)
{
    unsigned int ifindex = (unsigned int)if_nametoindex(ifname);
    int fd = socket(AF_PACKET, SOCK_RAW, (int)htons(ETH_P_ALL));
    struct sockaddr_ll sa = {0};
    unsigned char frame[60] = {0};
    ssize_t n;

    if (ifindex == 0 || fd < 0)
        return -1;
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = (__be16)htons(ETH_P_ALL);
    sa.sll_ifindex = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    frame[12] = 0x88;   /* arbitrary ethertype; nodes don't parse */
    frame[13] = 0xb8;
    n = write(fd, frame, sizeof(frame));
    close(fd);
    return (n == (ssize_t)sizeof(frame)) ? 0 : -1;
}

int main(void)
{
    struct xgl_graph *g;
    struct egl_graph *egl;
    struct egl_node_stats stats;
    const char *veth = "xglxit0";
    char cmd[256];
    int err, i;

    if (!have_bpf()) {
        printf("SKIP: no CAP_BPF\n");
        return 77;
    }

    snprintf(cmd, sizeof(cmd),
             "ip link add %s numrxqueues 1 numtxqueues 1 type veth "
             "peer name xglxit1 numrxqueues 1 numtxqueues 1", veth);
    if (system(cmd) != 0) {
        printf("SKIP: cannot create veth\n");
        return 77;
    }
    snprintf(cmd, sizeof(cmd), "ip link set %s up; ip link set xglxit1 up",
             veth);
    (void)system(cmd);

    g = xgl_graph_create("exit-test", 0);
    if (!g) {
        printf("FAIL: graph create\n");
        return 1;
    }

    /* Unbound exit must fail add_node. */
    err = xgl_graph_add_node(g, 0, OBJ_A, "exit_node_a");
    if (err != -ENOENT) {
        printf("FAIL: expected -ENOENT for unbound exit, got %d\n", err);
        return 1;
    }

    /* Bind "next" to slot 2 and compose. */
    if (xgl_graph_bind_exit(g, "exit_node_a", "next", 2) != 0) {
        printf("FAIL: bind\n");
        return 1;
    }
    if (xgl_graph_add_node(g, 2, OBJ_B, "exit_node_b") != 0) {
        printf("FAIL: add node B\n");
        return 1;
    }
    /* exit_node_a is the root (slot 0). */
    if (xgl_graph_add_node(g, 0, OBJ_A, "exit_node_a") != 0) {
        printf("FAIL: add node A (patched)\n");
        return 1;
    }
    /* Register the edge for DAG bookkeeping (slot 0 -> slot 2). */
    xgl_graph_add_edge(g, 0, 2);

    if (xgl_graph_attach(g, veth) != 0) {
        printf("FAIL: attach\n");
        return 1;
    }

    /* Inject a few frames from the peer. */
    for (i = 0; i < 5; i++)
        (void)inject("xglxit1");
    usleep(200000);

    /* If the patched tail call reached the bound node, slot 2 has
     * RX stats. */
    egl = xgl_graph_get_egl(g);
    if (egl_stats_read(egl, 2, &stats) != 0) {
        printf("FAIL: stats read\n");
        return 1;
    }
    if (stats.in_count == 0) {
        printf("FAIL: bound node saw no packets "
               "(tail call did not reach slot 2)\n");
        return 1;
    }

    printf("PASS: named exit reached bound slot (%llu packets)\n",
           (unsigned long long)stats.in_count);

    xgl_graph_destroy(g);
    snprintf(cmd, sizeof(cmd), "ip link del %s", veth);
    (void)system(cmd);
    return 0;
}
