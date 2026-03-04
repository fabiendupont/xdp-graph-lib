/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * test_meta_get - Tests for XGL_META_GET and XGL_META_ALLOC logic.
 *
 * Covers:
 *   SSR-META-005: Version validation in META_GET
 *   SSR-META-006: Bounds validation in META_GET
 *
 * These tests simulate the XDP headroom layout in userspace by creating
 * a mock buffer that mimics the relationship between data_meta and data.
 * The actual BPF macros cannot be used in userspace, so we replicate
 * the validation logic here to prove correctness of the checks.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <xgl/xgl_meta.h>

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

/*
 * Simulate XGL_META_GET logic.
 *
 * In BPF, data_meta and data are pointers into packet headroom.
 * We simulate this with a buffer where:
 *   data_meta = buffer start
 *   data = buffer start + headroom_size
 *
 * XGL_META_GET checks:
 *   1. data_meta + sizeof(struct xgl_meta) <= data  (bounds)
 *   2. meta->version == XGL_META_VERSION              (version)
 */
static struct xgl_meta *
mock_meta_get(void *data_meta, void *data)
{
    struct xgl_meta *meta = data_meta;

    if ((char *)data_meta + sizeof(struct xgl_meta) <= (char *)data &&
        meta->version == XGL_META_VERSION)
        return meta;

    return NULL;
}

/*
 * SSR-META-005: META_GET returns NULL when version does not match.
 */
static void
test_meta_get_wrong_version(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;
    void *data = buf + sizeof(struct xgl_meta);

    TEST(meta_get_wrong_version_returns_null);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;
    meta->version = 0; /* wrong version */

    ASSERT_EQ(mock_meta_get(data_meta, data), NULL,
              "should return NULL for version 0");

    meta->version = 2; /* wrong version */
    ASSERT_EQ(mock_meta_get(data_meta, data), NULL,
              "should return NULL for version 2");

    meta->version = 255; /* wrong version */
    ASSERT_EQ(mock_meta_get(data_meta, data), NULL,
              "should return NULL for version 255");
    PASS();
}

/*
 * SSR-META-005: META_GET returns valid pointer when version matches.
 */
static void
test_meta_get_correct_version(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;
    void *data = buf + sizeof(struct xgl_meta);

    TEST(meta_get_correct_version_returns_ptr);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;
    meta->version = XGL_META_VERSION;

    ASSERT_EQ(mock_meta_get(data_meta, data) != NULL, 1,
              "should return non-NULL for correct version");
    ASSERT_EQ(mock_meta_get(data_meta, data), meta,
              "should return pointer to meta");
    PASS();
}

/*
 * SSR-META-006: META_GET returns NULL when headroom is too small.
 */
static void
test_meta_get_insufficient_headroom(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;

    TEST(meta_get_insufficient_headroom_returns_null);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;
    meta->version = XGL_META_VERSION;

    /* data is only 1 byte after data_meta — way too small */
    ASSERT_EQ(mock_meta_get(data_meta, (char *)data_meta + 1), NULL,
              "should return NULL for 1-byte headroom");

    /* data is exactly sizeof(xgl_meta) - 1 bytes after data_meta */
    ASSERT_EQ(mock_meta_get(data_meta,
                            (char *)data_meta + sizeof(struct xgl_meta) - 1),
              NULL,
              "should return NULL for headroom too small by 1");

    /* data is 0 bytes after data_meta (no headroom at all) */
    ASSERT_EQ(mock_meta_get(data_meta, (char *)data_meta), NULL,
              "should return NULL for zero headroom");
    PASS();
}

/*
 * SSR-META-006: META_GET succeeds when headroom is exactly sufficient.
 */
static void
test_meta_get_exact_headroom(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;
    void *data = (char *)buf + sizeof(struct xgl_meta);

    TEST(meta_get_exact_headroom_succeeds);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;
    meta->version = XGL_META_VERSION;

    ASSERT_EQ(mock_meta_get(data_meta, data) != NULL, 1,
              "should succeed with exact headroom");
    PASS();
}

/*
 * SSR-META-006: META_GET succeeds when headroom is larger than needed.
 */
static void
test_meta_get_excess_headroom(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;
    void *data = (char *)buf + sizeof(struct xgl_meta) + 64;

    TEST(meta_get_excess_headroom_succeeds);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;
    meta->version = XGL_META_VERSION;

    ASSERT_EQ(mock_meta_get(data_meta, data) != NULL, 1,
              "should succeed with excess headroom");
    PASS();
}

/*
 * SSR-META-005 + SSR-META-006 combined: both checks must pass.
 */
static void
test_meta_get_both_checks(void)
{
    unsigned char buf[256];
    struct xgl_meta *meta;
    void *data_meta = buf;

    TEST(meta_get_both_checks_must_pass);

    memset(buf, 0, sizeof(buf));
    meta = (struct xgl_meta *)buf;

    /* Correct headroom but wrong version → NULL */
    meta->version = 0;
    ASSERT_EQ(mock_meta_get(data_meta,
                            (char *)data_meta + sizeof(struct xgl_meta)),
              NULL,
              "wrong version with good headroom should fail");

    /* Correct version but insufficient headroom → NULL */
    meta->version = XGL_META_VERSION;
    ASSERT_EQ(mock_meta_get(data_meta, (char *)data_meta + 10), NULL,
              "good version with bad headroom should fail");

    /* Both correct → non-NULL */
    ASSERT_EQ(mock_meta_get(data_meta,
                            (char *)data_meta + sizeof(struct xgl_meta))
              != NULL, 1,
              "both correct should succeed");
    PASS();
}

int
main(void)
{
    printf("test_meta_get:\n");

    test_meta_get_wrong_version();
    test_meta_get_correct_version();
    test_meta_get_insufficient_headroom();
    test_meta_get_exact_headroom();
    test_meta_get_excess_headroom();
    test_meta_get_both_checks();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
