/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * Unprivileged unit tests for named exits: declaration reading and
 * immediate patching (pure ELF work, no CAP_BPF needed).
 */

#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <xgl/xgl_exits.h>
#include <xgl/xgl_graph.h>

/* internal, implemented in xgl_exits.c */
int xgl_patch_exit_immediates(const char *in_path, const char *out_path,
                              const uint32_t *ids, const uint32_t *slots,
                              size_t n);

#ifndef EXIT_OBJ_DIR
#define EXIT_OBJ_DIR "."
#endif

#define OBJ_A EXIT_OBJ_DIR "/exit_node_a.bpf.o"

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

/* raw ELF scan for mov32-imm instructions (BPF code 0xb4) */
static int count_mov32_imm(const char *path, int32_t want, int *found)
{
    FILE *f = fopen(path, "rb");
    unsigned char buf[8];
    int count = 0;

    *found = 0;
    if (!f)
        return -1;
    while (fread(buf, 1, 8, f) == 8) {
        if (buf[0] == 0xb4) {
            int32_t imm;
            memcpy(&imm, buf + 4, 4);
            if (imm == want)
                count++;
        }
    }
    fclose(f);
    *found = 1;
    return count;
}

static void test_read_decls(void)
{
    struct xgl_exit_meta *decls = NULL;
    size_t n = 0;

    CHECK(xgl_read_exit_decls(OBJ_A, &decls, &n) == 0);
    CHECK(n == 1);
    if (n == 1) {
        CHECK(strcmp(decls[0].name, "next") == 0);
        CHECK(decls[0].id < 65536);   /* fits the magic's id field */
    }
    free(decls);

    /* Objects without exits: -ENOENT. */
    CHECK(xgl_read_exit_decls(EXIT_OBJ_DIR "/xgl_dispatch.bpf.o",
                              &decls, &n) == -ENOENT);
}

static void test_patch(void)
{
    struct xgl_exit_meta *decls = NULL;
    size_t n = 0;
    uint32_t ids[8], slots[8];
    char tmpl[] = "/tmp/xgl-exit-test-XXXXXX";
    int fd, ok;
    int magic_count, slot_count;

    CHECK(xgl_read_exit_decls(OBJ_A, &decls, &n) == 0);
    CHECK(n == 1);
    if (n != 1)
        return;
    ids[0] = decls[0].id;
    slots[0] = 7;   /* bind "next" to slot 7 */
    free(decls);

    fd = mkstemp(tmpl);
    if (fd < 0)
        return;
    close(fd);

    /* Before patching: exactly one magic immediate. */
    magic_count = count_mov32_imm(OBJ_A,
        (int32_t)(XGL_EXIT_MAGIC_BASE | ids[0]), &ok);
    CHECK(ok && magic_count == 1);
    if (!ok || magic_count != 1) {
        unlink(tmpl);
        return;
    }

    CHECK(xgl_patch_exit_immediates(OBJ_A, tmpl, ids, slots, 1) == 0);

    /* After patching: no magic left, one immediate equal to 7. */
    magic_count = count_mov32_imm(tmpl,
        (int32_t)(XGL_EXIT_MAGIC_BASE | ids[0]), &ok);
    CHECK(ok && magic_count == 0);
    slot_count = count_mov32_imm(tmpl, 7, &ok);
    CHECK(ok && slot_count >= 1);

    unlink(tmpl);
}

static void test_unbound_patch_fails(void)
{
    /* Patching with no bindings for the id must fail -ENOENT. */
    char tmpl[] = "/tmp/xgl-exit-test-XXXXXX";
    uint32_t ids[1] = { 0xFFFF };   /* no such id anywhere */
    uint32_t slots[1] = { 1 };
    int fd;

    fd = mkstemp(tmpl);
    if (fd < 0)
        return;
    close(fd);

    /* The object's real exit id IS present in the instruction
     * stream, and has no binding in this call -> -ENOENT. */
    CHECK(xgl_patch_exit_immediates(OBJ_A, tmpl, ids, slots, 1) == -ENOENT);
    unlink(tmpl);
}

int main(void)
{
    test_read_decls();
    test_patch();
    test_unbound_patch_fails();

    if (failures == 0) {
        printf("xgl_exits tests: all passed\n");
        return 0;
    }
    printf("xgl_exits tests: %d failure(s)\n", failures);
    return 1;
}
