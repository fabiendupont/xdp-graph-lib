/* SPDX-License-Identifier: BSD-2-Clause */

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

static void
test_sizeof(void)
{
    TEST(sizeof_xgl_meta_is_52);
    _Static_assert(sizeof(struct xgl_meta) == 52,
                   "xgl_meta must be exactly 52 bytes");
    ASSERT_EQ(sizeof(struct xgl_meta), 52, "sizeof(xgl_meta) != 52");
    PASS();
}

static void
test_fits_in_headroom(void)
{
    TEST(meta_fits_in_headroom);
    _Static_assert(sizeof(struct xgl_meta) <= XGL_MAX_HEADROOM,
                   "xgl_meta must fit in headroom");
    ASSERT_EQ(sizeof(struct xgl_meta) <= XGL_MAX_HEADROOM, 1,
              "xgl_meta exceeds XGL_MAX_HEADROOM");
    PASS();
}

static void
test_alignment(void)
{
    TEST(meta_alignment_is_4);
    ASSERT_EQ(__alignof__(struct xgl_meta), 4, "alignment != 4");
    PASS();
}

static void
test_field_offsets(void)
{
    TEST(field_offsets);
    ASSERT_EQ(offsetof(struct xgl_meta, version), 0, "version offset");
    ASSERT_EQ(offsetof(struct xgl_meta, flags), 1, "flags offset");
    ASSERT_EQ(offsetof(struct xgl_meta, l2_proto), 2, "l2_proto offset");
    ASSERT_EQ(offsetof(struct xgl_meta, l3_offset), 4, "l3_offset offset");
    ASSERT_EQ(offsetof(struct xgl_meta, next_node), 6, "next_node offset");
    ASSERT_EQ(offsetof(struct xgl_meta, ingress_ifindex), 8,
              "ingress_ifindex offset");
    ASSERT_EQ(offsetof(struct xgl_meta, timestamp_ns), 12,
              "timestamp_ns offset");
    ASSERT_EQ(offsetof(struct xgl_meta, scratch), 20, "scratch offset");
    PASS();
}

static void
test_flag_constants(void)
{
    TEST(flag_constants);
    ASSERT_EQ(XGL_FLAG_DROP, 1U, "XGL_FLAG_DROP != 1");
    ASSERT_EQ(XGL_FLAG_PASS, 2U, "XGL_FLAG_PASS != 2");
    ASSERT_EQ(XGL_FLAG_REDIRECT, 4U, "XGL_FLAG_REDIRECT != 4");
    PASS();
}

static void
test_zero_init(void)
{
    struct xgl_meta meta;
    unsigned char *p = (unsigned char *)&meta;

    TEST(zero_init);
    memset(&meta, 0, sizeof(meta));

    for (size_t i = 0; i < sizeof(meta); i++) {
        ASSERT_EQ(p[i], 0, "non-zero byte after memset");
    }

    ASSERT_EQ(meta.version, 0, "version not 0");
    ASSERT_EQ(meta.flags, 0, "flags not 0");
    ASSERT_EQ(meta.l2_proto, 0, "l2_proto not 0");
    ASSERT_EQ(meta.l3_offset, 0, "l3_offset not 0");
    ASSERT_EQ(meta.next_node, 0, "next_node not 0");
    ASSERT_EQ(meta.ingress_ifindex, 0, "ingress_ifindex not 0");
    ASSERT_EQ(meta.timestamp_ns, 0, "timestamp_ns not 0");
    PASS();
}

static void
test_version_constant(void)
{
    TEST(version_constant);
    ASSERT_EQ(XGL_META_VERSION, 1, "XGL_META_VERSION != 1");
    PASS();
}

static void
test_scratch_size(void)
{
    TEST(scratch_size);
    ASSERT_EQ(XGL_SCRATCH_SIZE, 32, "XGL_SCRATCH_SIZE != 32");
    ASSERT_EQ(sizeof(((struct xgl_meta *)0)->scratch), 32,
              "scratch field size != 32");
    PASS();
}

int
main(void)
{
    printf("test_meta:\n");

    test_sizeof();
    test_fits_in_headroom();
    test_alignment();
    test_field_offsets();
    test_flag_constants();
    test_zero_init();
    test_version_constant();
    test_scratch_size();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
