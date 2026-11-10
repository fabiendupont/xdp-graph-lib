/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_EXITS_H
#define XGL_EXITS_H

#include <linux/types.h>

/*
 * Shared (userspace + BPF) definitions for named tail-call exits.
 * The BPF-side macros live in xgl/bpf/xgl_exits.bpf.h.
 */

#define XGL_EXIT_MAGIC_BASE  0x7E000000U
#define XGL_EXIT_MAGIC_MASK  0xFFFF0000U

struct xgl_exit_meta {
    char  name[32];
    __u32 id;
} __attribute__((packed, aligned(4)));

#endif /* XGL_EXITS_H */
