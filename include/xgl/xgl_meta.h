/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_META_H
#define XGL_META_H

#include <linux/types.h>

#define XGL_META_VERSION  1
#define XGL_SCRATCH_SIZE  32
#define XGL_MAX_HEADROOM  252

#define XGL_FLAG_DROP      (1U << 0)
#define XGL_FLAG_PASS      (1U << 1)
#define XGL_FLAG_REDIRECT  (1U << 2)

struct xgl_meta {
    __u8  version;           /* Must be XGL_META_VERSION */
    __u8  flags;             /* XGL_FLAG_DROP, XGL_FLAG_PASS, XGL_FLAG_REDIRECT */
    __u16 l2_proto;          /* EtherType (after VLAN strip) */
    __u16 l3_offset;         /* Byte offset from data to L3 header */
    __u16 next_node;         /* Index into PROG_ARRAY for next tail call */
    __u32 ingress_ifindex;   /* Original ingress interface */
    __u64 timestamp_ns;      /* Arrival timestamp (bpf_ktime_get_ns) */
    /*
     * Scratch area — inter-node communication buffer.
     *
     * OWNERSHIP RULES (FM-META-05):
     *   - Each pipeline defines a scratch layout struct shared by
     *     all nodes that read/write scratch (e.g., struct my_scratch).
     *   - Nodes that produce scratch data MUST document which fields
     *     they write.
     *   - Nodes that consume scratch data MUST document which fields
     *     they read and which upstream node produces them.
     *   - Two nodes MUST NOT write the same scratch field unless the
     *     pipeline topology guarantees they never execute on the
     *     same packet (i.e., they are on mutually exclusive branches).
     *   - The dispatcher (root node) zero-initializes scratch via
     *     XGL_META_ALLOC. Nodes MUST NOT assume scratch contains
     *     valid data unless a known upstream node has written it.
     */
    __u8  scratch[XGL_SCRATCH_SIZE];
} __attribute__((packed, aligned(4)));

_Static_assert(sizeof(struct xgl_meta) == 52,
               "xgl_meta must be exactly 52 bytes");
_Static_assert(sizeof(struct xgl_meta) <= XGL_MAX_HEADROOM,
               "xgl_meta must fit within XDP headroom");

#endif /* XGL_META_H */
