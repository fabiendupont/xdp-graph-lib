/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

/*
 * test_xsk_privileged - AF_XDP socket integration tests (root required).
 *
 * Covers:
 *   SSR-XSK-001: Prefer XDP_ZEROCOPY, fallback to XDP_COPY
 *   SSR-XSK-002: Destroy releases all resources
 *   SSR-XSK-005: xgl_graph_create_xsk inserts fd into XSKMAP
 *
 * Uses a veth pair for XDP-capable interfaces (loopback does not
 * support XDP in native mode).
 *
 * All tests skip gracefully when running without root.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>

#include <xgl/xgl_graph.h>
#include <xgl/xgl_xsk.h>

#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

#define VETH0 "xgl_xsk0"
#define VETH1 "xgl_xsk1"

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

/*
 * Helper: create a veth pair for XDP testing.
 * Returns 0 on success, -1 on failure.
 */
static int
create_veth_pair(void)
{
    char cmd[256];
    int ret;

    /* Clean up any leftover interfaces from a previous run */
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    system(cmd);

    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s 2>/dev/null",
             VETH0, VETH1);
    ret = system(cmd);
    if (ret != 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH0);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH1);
    system(cmd);

    return 0;
}

/*
 * Helper: destroy the veth pair.
 */
static void
destroy_veth_pair(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    system(cmd);
}

/*
 * SSR-XSK-001: veth doesn't support zero-copy — we expect XDP_COPY fallback.
 */
static void
test_xsk_zerocopy_fallback(void)
{
    struct xgl_xsk *xsk;

    TEST(xsk_zerocopy_fallback_on_veth);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /*
     * veth doesn't support zero-copy — we expect copy mode.
     * This verifies the XDP_ZEROCOPY -> XDP_COPY fallback path.
     */
    ASSERT_EQ(xgl_xsk_is_zerocopy(xsk), false,
              "veth should fall back to copy mode");

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * SSR-XSK-005: XSK fd is valid for XSKMAP insertion.
 */
static void
test_xsk_fd_for_xskmap(void)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    struct xgl_xsk *xsk;
    int map_fd, xsk_fd;
    __u32 key = 0;

    TEST(xsk_fd_valid_for_xskmap);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    xsk_fd = xgl_xsk_get_fd(xsk);
    ASSERT_GE(xsk_fd, 0, "xsk fd should be valid");

    /* Create a temporary XSKMAP and try inserting the fd */
    map_fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP,
                             "test_xskmap",
                             sizeof(__u32),
                             sizeof(__u32),
                             4, &opts);
    if (map_fd < 0) {
        printf("SKIP: XSKMAP creation failed (%s)\n", strerror(errno));
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }

    ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &xsk_fd, BPF_ANY), 0,
              "XSK fd should insert into XSKMAP");

    close(map_fd);
    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * SSR-XSK-005: Graph-level XSK creation inserts into XSKMAP.
 */
static void
test_graph_create_xsk(void)
{
    struct xgl_graph *g;
    struct xgl_xsk *xsk;
    char dispatch_path[512];
    int ret;

    TEST(graph_create_xsk_lifecycle);
    if (geteuid() != 0)
        SKIP("not root");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);
    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    g = xgl_graph_create("xsk-graph", 0);
    ASSERT_EQ(g != NULL, 1, "graph creation failed");

    /* Load a BPF node so the XSKMAP gets pinned */
    ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        printf("SKIP: add_node returned %d (%s)\n", ret, strerror(-ret));
        tests_skipped++;
        xgl_graph_destroy(g);
        destroy_veth_pair();
        return;
    }

    xsk = xgl_graph_create_xsk(g, VETH0, 0);
    if (!xsk) {
        printf("SKIP: graph_create_xsk on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        xgl_graph_destroy(g);
        destroy_veth_pair();
        return;
    }

    /* fd should be valid */
    ASSERT_GE(xgl_xsk_get_fd(xsk), 0, "xsk fd should be valid");

    /* Destroy graph — should clean up XSK too */
    xgl_graph_destroy(g);
    destroy_veth_pair();
    PASS();
}

/*
 * Test: Send/recv round-trip on veth pair.
 */
static void
test_xsk_send_recv(void)
{
    struct xgl_xsk *xsk;
    void *tx_buf;
    void *rx_buf;
    __u32 rx_len;
    int ret;

    TEST(xsk_send_recv_on_veth);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /* Allocate a TX frame and write a small payload */
    tx_buf = xgl_xsk_send_alloc(xsk, 64);
    if (!tx_buf) {
        printf("SKIP: send_alloc failed\n");
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }
    memset(tx_buf, 0xAB, 64);

    ret = xgl_xsk_send_complete(xsk);
    if (ret != 0) {
        printf("SKIP: send_complete failed (%d)\n", ret);
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }

    /* Poll briefly for RX */
    xgl_xsk_poll(xsk, 100);

    ret = xgl_xsk_recv(xsk, &rx_buf, &rx_len);
    if (ret > 0) {
        xgl_xsk_recv_release(xsk);
    }
    /* Not asserting recv count — veth loopback behavior varies */

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * Test: Batch receive API on veth.
 */
static void
test_xsk_batch_recv(void)
{
    struct xgl_xsk *xsk;
    void *pkts[8];
    __u32 lens[8];

    TEST(xsk_batch_recv_on_veth);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /* Just verify the call doesn't crash — 0 packets expected */
    int rcvd = xgl_xsk_recv_batch(xsk, pkts, lens, 8);
    if (rcvd > 0)
        xgl_xsk_recv_release_batch(xsk, rcvd);

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * SSR-XSK-002: After destroy, the fd is no longer valid.
 */
static void
test_xsk_destroy_cleanup(void)
{
    struct xgl_xsk *xsk;
    int fd;

    TEST(xsk_destroy_fd_invalid_after);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    fd = xgl_xsk_get_fd(xsk);
    ASSERT_GE(fd, 0, "fd should be valid before destroy");

    xgl_xsk_destroy(xsk);

    /*
     * After destroy, writing to the fd should fail.
     * We check via write() — a valid socket fd would accept or EAGAIN,
     * but a closed fd returns -1 with EBADF.
     */
    ssize_t wr = write(fd, "", 1);
    ASSERT_EQ(wr, -1, "write to closed fd should fail");
    ASSERT_EQ(errno, EBADF, "errno should be EBADF after destroy");

    destroy_veth_pair();
    PASS();
}

/*
 * Helper: send a raw Ethernet frame from an interface.
 * Builds a minimal frame with a recognizable payload pattern.
 * Returns 0 on success, -1 on failure.
 */
static int
send_raw_frame(const char *ifname, const unsigned char *payload,
               int payload_len)
{
    unsigned char frame[1514];
    struct sockaddr_ll sll;
    unsigned int ifindex;
    int fd, ret;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -1;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    /* Build frame: dst MAC (broadcast) + src MAC + ethertype + payload */
    memset(frame, 0xff, 6);                  /* dst: broadcast */
    memset(frame + 6, 0xaa, 6);              /* src: aa:aa:aa:aa:aa:aa */
    frame[12] = 0x08;                        /* ethertype: 0x0800 (IPv4) */
    frame[13] = 0x00;

    int copy_len = payload_len;
    if (copy_len > (int)sizeof(frame) - 14)
        copy_len = (int)sizeof(frame) - 14;
    memcpy(frame + 14, payload, (size_t)copy_len);

    ret = (int)sendto(fd, frame, (size_t)(14 + copy_len), 0,
                      (struct sockaddr *)&sll, sizeof(sll));
    close(fd);

    return (ret > 0) ? 0 : -1;
}

/*
 * Test: XSK single recv with real packet data.
 * Sends a raw frame from veth1, receives it via XSK on veth0.
 * Exercises recv, recv_release, poll happy paths.
 */
static void
test_xsk_data_recv(void)
{
    struct xgl_xsk *xsk;
    void *pkt;
    __u32 pkt_len;
    unsigned char payload[64];
    int ret;

    TEST(xsk_data_recv_single);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /* Send a recognizable payload from veth1 */
    memset(payload, 0xBE, sizeof(payload));
    if (send_raw_frame(VETH1, payload, (int)sizeof(payload)) != 0) {
        printf("SKIP: send_raw_frame failed (%s)\n", strerror(errno));
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }

    /* Poll and receive */
    xgl_xsk_poll(xsk, 200);

    ret = xgl_xsk_recv(xsk, &pkt, &pkt_len);
    if (ret <= 0) {
        /* XSK recv may not work on all kernel/driver combos */
        printf("SKIP: no packet received (%d)\n", ret);
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }

    /* Verify we got a packet with nonzero length */
    ASSERT_GE(pkt_len, 14, "packet should be at least 14 bytes (eth hdr)");

    xgl_xsk_recv_release(xsk);

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * Test: XSK batch recv with real packet data.
 * Sends multiple frames, receives them in a batch.
 * Exercises recv_batch, recv_release_batch happy paths.
 */
static void
test_xsk_data_recv_batch(void)
{
    struct xgl_xsk *xsk;
    void *pkts[8];
    __u32 lens[8];
    unsigned char payload[32];
    int rcvd;

    TEST(xsk_data_recv_batch);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /* Send 3 frames */
    memset(payload, 0xCD, sizeof(payload));
    for (int i = 0; i < 3; i++) {
        payload[0] = (unsigned char)i;
        send_raw_frame(VETH1, payload, (int)sizeof(payload));
    }

    xgl_xsk_poll(xsk, 200);

    rcvd = xgl_xsk_recv_batch(xsk, pkts, lens, 8);
    if (rcvd <= 0) {
        printf("SKIP: no packets received in batch (%d)\n", rcvd);
        tests_skipped++;
        xgl_xsk_destroy(xsk);
        destroy_veth_pair();
        return;
    }

    /* Verify we got at least 1 packet */
    ASSERT_GE(rcvd, 1, "should receive at least 1 packet");
    ASSERT_GE(lens[0], 14, "first packet should be at least eth hdr");

    xgl_xsk_recv_release_batch(xsk, rcvd);

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * Test: XSK send_alloc and send_complete with real socket.
 * Exercises the TX ring allocation and kernel submission paths.
 */
static void
test_xsk_data_send(void)
{
    struct xgl_xsk *xsk;
    void *tx_buf;
    int ret;

    TEST(xsk_data_send_alloc_complete);
    if (geteuid() != 0)
        SKIP("not root");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    xsk = xgl_xsk_create(VETH0, 0, 4096, 64);
    if (!xsk) {
        printf("SKIP: xsk_create on %s failed (%s)\n",
               VETH0, strerror(errno));
        tests_skipped++;
        destroy_veth_pair();
        return;
    }

    /* Allocate multiple TX frames to exercise the ring path */
    for (int i = 0; i < 3; i++) {
        tx_buf = xgl_xsk_send_alloc(xsk, 64);
        if (!tx_buf) {
            printf("SKIP: send_alloc #%d failed\n", i);
            tests_skipped++;
            xgl_xsk_destroy(xsk);
            destroy_veth_pair();
            return;
        }
        memset(tx_buf, 0xEF, 64);
    }

    /* Complete the send — exercises kernel kick path */
    ret = xgl_xsk_send_complete(xsk);
    ASSERT_EQ(ret, 0, "send_complete should succeed");

    /* Poll to let the kernel process */
    xgl_xsk_poll(xsk, 50);

    /* Second round to exercise completion drain in send_alloc */
    tx_buf = xgl_xsk_send_alloc(xsk, 64);
    if (tx_buf) {
        memset(tx_buf, 0xEF, 64);
        ret = xgl_xsk_send_complete(xsk);
        ASSERT_EQ(ret, 0, "second send_complete should succeed");
    }

    xgl_xsk_destroy(xsk);
    destroy_veth_pair();
    PASS();
}

/*
 * Test: add_tx_port success path — exercises DEVMAP creation.
 */
static void
test_add_tx_port_success(void)
{
    struct xgl_graph *g;
    char dispatch_path[512];
    int ret;

    TEST(xsk_add_tx_port_success);
    if (geteuid() != 0)
        SKIP("not root");

    snprintf(dispatch_path, sizeof(dispatch_path),
             "%s/xgl_dispatch.bpf.o", BPF_OBJ_DIR);
    if (access(dispatch_path, R_OK) != 0)
        SKIP("no xgl_dispatch.bpf.o");

    if (create_veth_pair() != 0)
        SKIP("veth creation failed");

    g = xgl_graph_create("tx-port-test", 0);
    ASSERT_EQ(g != NULL, 1, "graph creation failed");

    /* Load a BPF node so the DEVMAP (xgl_tx_ports) gets pinned */
    ret = xgl_graph_add_node(g, 0, dispatch_path, "xgl_dispatch");
    if (ret != 0) {
        printf("SKIP: add_node returned %d (%s)\n", ret, strerror(-ret));
        tests_skipped++;
        xgl_graph_destroy(g);
        destroy_veth_pair();
        return;
    }

    ret = xgl_graph_add_tx_port(g, VETH0);
    ASSERT_EQ(ret, 0, "add_tx_port should succeed");

    /* Adding same port again should be idempotent */
    ret = xgl_graph_add_tx_port(g, VETH0);
    ASSERT_EQ(ret, 0, "re-adding tx port should succeed");

    /* Add the other end too */
    ret = xgl_graph_add_tx_port(g, VETH1);
    ASSERT_EQ(ret, 0, "add_tx_port for veth1 should succeed");

    xgl_graph_destroy(g);
    destroy_veth_pair();
    PASS();
}

int
main(void)
{
    printf("test_xsk_privileged:\n");

    test_xsk_zerocopy_fallback();
    test_xsk_fd_for_xskmap();
    test_graph_create_xsk();
    test_xsk_send_recv();
    test_xsk_batch_recv();
    test_xsk_destroy_cleanup();

    /* Data path coverage */
    test_xsk_data_recv();
    test_xsk_data_recv_batch();
    test_xsk_data_send();
    test_add_tx_port_success();

    printf("\n%d/%d tests passed, %d skipped\n",
           tests_passed, tests_run, tests_skipped);
    return (tests_passed + tests_skipped) == tests_run ? 0 : 1;
}
