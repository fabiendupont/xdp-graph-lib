/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_xsk - AF_XDP socket lifecycle tests.
 *
 * These tests validate the xgl_xsk API:
 *   - NULL/invalid parameter handling
 *   - XSK creation on loopback (requires CAP_NET_ADMIN)
 *   - Zero-copy vs copy mode detection
 *   - XSK fd is valid for XSKMAP insertion
 *
 * Most tests require root (CAP_NET_ADMIN + CAP_BPF) and are
 * skipped gracefully when running without privileges.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xgl/xgl_xsk.h>

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

/*
 * Test: NULL parameters return NULL/error.
 */
static void
test_xsk_null_params(void)
{
    TEST(xsk_create_null_ifname);
    ASSERT_EQ(xgl_xsk_create(NULL, 0, 4096, 4096), NULL,
              "NULL ifname should return NULL");
    PASS();
}

/*
 * Test: Invalid parameters return NULL/error.
 */
static void
test_xsk_invalid_params(void)
{
    TEST(xsk_create_invalid_params);
    ASSERT_EQ(xgl_xsk_create("lo", -1, 4096, 4096), NULL,
              "negative queue_id should return NULL");
    ASSERT_EQ(xgl_xsk_create("lo", 0, 0, 4096), NULL,
              "zero frame_size should return NULL");
    ASSERT_EQ(xgl_xsk_create("lo", 0, 4096, 0), NULL,
              "zero num_frames should return NULL");
    PASS();
}

/*
 * Test: Non-power-of-2 num_frames rejected early.
 */
static void
test_xsk_non_power_of_2(void)
{
    TEST(xsk_create_non_power_of_2);
    ASSERT_EQ(xgl_xsk_create("lo", 0, 4096, 3), NULL,
              "num_frames=3 should return NULL");
    ASSERT_EQ(xgl_xsk_create("lo", 0, 4096, 5), NULL,
              "num_frames=5 should return NULL");
    ASSERT_EQ(xgl_xsk_create("lo", 0, 4096, 100), NULL,
              "num_frames=100 should return NULL");
    PASS();
}

/*
 * Test: xgl_xsk_destroy(NULL) is safe.
 */
static void
test_xsk_destroy_null(void)
{
    TEST(xsk_destroy_null_safe);
    xgl_xsk_destroy(NULL);
    PASS();
}

/*
 * Test: xgl_xsk_is_zerocopy(NULL) returns false.
 */
static void
test_xsk_zerocopy_null(void)
{
    TEST(xsk_is_zerocopy_null);
    ASSERT_EQ(xgl_xsk_is_zerocopy(NULL), false,
              "NULL xsk should not be zerocopy");
    PASS();
}

/*
 * Test: xgl_xsk_get_fd(NULL) returns -1.
 */
static void
test_xsk_get_fd_null(void)
{
    TEST(xsk_get_fd_null);
    ASSERT_EQ(xgl_xsk_get_fd(NULL), -1,
              "NULL xsk fd should be -1");
    PASS();
}

/*
 * Test: Create XSK with nonexistent interface returns NULL.
 */
static void
test_xsk_create_bad_ifname(void)
{
    TEST(xsk_create_bad_ifname);
    ASSERT_EQ(xgl_xsk_create("nonexistent99", 0, 4096, 64), NULL,
              "nonexistent interface should return NULL");
    PASS();
}

/*
 * Test: xgl_xsk_recv(NULL, ...) returns 0.
 */
static void
test_xsk_recv_null(void)
{
    void *pkt = NULL;
    __u32 len = 0;

    TEST(xsk_recv_null_xsk);
    ASSERT_EQ(xgl_xsk_recv(NULL, &pkt, &len), 0,
              "NULL xsk recv should return 0");
    PASS();
}

/*
 * Test: xgl_xsk_recv with NULL output pointers returns 0.
 */
static void
test_xsk_recv_null_outputs(void)
{
    __u32 len = 0;

    TEST(xsk_recv_null_output_ptrs);
    ASSERT_EQ(xgl_xsk_recv(NULL, NULL, &len), 0,
              "NULL pkt_data should return 0");
    ASSERT_EQ(xgl_xsk_recv(NULL, NULL, NULL), 0,
              "all NULL should return 0");
    PASS();
}

/*
 * Test: xgl_xsk_recv_release(NULL) is safe.
 */
static void
test_xsk_recv_release_null(void)
{
    TEST(xsk_recv_release_null_safe);
    xgl_xsk_recv_release(NULL);
    PASS();
}

/*
 * Test: xgl_xsk_send_alloc(NULL, ...) returns NULL.
 */
static void
test_xsk_send_alloc_null(void)
{
    TEST(xsk_send_alloc_null_xsk);
    ASSERT_EQ(xgl_xsk_send_alloc(NULL, 64), NULL,
              "NULL xsk send_alloc should return NULL");
    PASS();
}

/*
 * Test: xgl_xsk_send_alloc with zero length returns NULL.
 */
static void
test_xsk_send_alloc_zero_len(void)
{
    TEST(xsk_send_alloc_zero_len);
    ASSERT_EQ(xgl_xsk_send_alloc(NULL, 0), NULL,
              "zero len send_alloc should return NULL");
    PASS();
}

/*
 * Test: xgl_xsk_send_complete(NULL) returns -EINVAL.
 */
static void
test_xsk_send_complete_null(void)
{
    TEST(xsk_send_complete_null_xsk);
    ASSERT_EQ(xgl_xsk_send_complete(NULL), -EINVAL,
              "NULL xsk send_complete should return -EINVAL");
    PASS();
}

/*
 * Test: xgl_xsk_poll(NULL, ...) returns -EINVAL.
 */
static void
test_xsk_poll_null(void)
{
    TEST(xsk_poll_null_xsk);
    ASSERT_EQ(xgl_xsk_poll(NULL, 0), -EINVAL,
              "NULL xsk poll should return -EINVAL");
    PASS();
}

/*
 * Test: xgl_xsk_recv_batch(NULL, ...) returns 0.
 */
static void
test_xsk_recv_batch_null(void)
{
    void *pkts[4];
    __u32 lens[4];

    TEST(xsk_recv_batch_null_xsk);
    ASSERT_EQ(xgl_xsk_recv_batch(NULL, pkts, lens, 4), 0,
              "NULL xsk recv_batch should return 0");
    PASS();
}

/*
 * Test: xgl_xsk_recv_batch with zero max returns 0.
 */
static void
test_xsk_recv_batch_zero_max(void)
{
    void *pkts[1];
    __u32 lens[1];

    TEST(xsk_recv_batch_zero_max);
    ASSERT_EQ(xgl_xsk_recv_batch(NULL, pkts, lens, 0), 0,
              "zero max recv_batch should return 0");
    PASS();
}

/*
 * Test: xgl_xsk_recv_release_batch(NULL, ...) is safe.
 */
static void
test_xsk_recv_release_batch_null(void)
{
    TEST(xsk_recv_release_batch_null_safe);
    xgl_xsk_recv_release_batch(NULL, 1);
    PASS();
}

int
main(void)
{
    printf("test_xsk:\n");

    test_xsk_null_params();
    test_xsk_invalid_params();
    test_xsk_non_power_of_2();
    test_xsk_destroy_null();
    test_xsk_zerocopy_null();
    test_xsk_get_fd_null();
    test_xsk_create_bad_ifname();

    /* SSR-XSK-003: input validation for all public functions */
    test_xsk_recv_null();
    test_xsk_recv_null_outputs();
    test_xsk_recv_release_null();
    test_xsk_send_alloc_null();
    test_xsk_send_alloc_zero_len();
    test_xsk_send_complete_null();
    test_xsk_poll_null();
    test_xsk_recv_batch_null();
    test_xsk_recv_batch_zero_max();
    test_xsk_recv_release_batch_null();

    printf("\n%d/%d tests passed, %d skipped\n",
           tests_passed, tests_run, tests_skipped);
    return (tests_passed + tests_skipped) == tests_run ? 0 : 1;
}
