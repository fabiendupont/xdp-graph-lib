/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_NODE_H
#define XGL_NODE_H

#include <xgl/xgl_meta.h>
#include <egl/egl_node.h>

/*
 * XGL_NODE(name) - Declare an XDP graph node entry point.
 *
 * Usage:
 *   XGL_NODE(my_node) {
 *       struct xgl_meta *meta = XGL_META_GET(ctx);
 *       if (!meta) return XDP_DROP;
 *       ...
 *   }
 */
#define XGL_NODE(name)  SEC("xdp") int name(struct xdp_md *ctx)

/*
 * XGL_META_GET(ctx) - Read metadata from XDP headroom.
 *
 * Returns: pointer to xgl_meta, or NULL if headroom is not allocated
 *          or version does not match XGL_META_VERSION.
 *
 * Preconditions:
 *   - ctx is a valid xdp_md pointer
 *   - XGL_META_ALLOC() was called by the root node
 *
 * Postconditions:
 *   - returned pointer is within [data_meta, data) bounds
 *   - version field equals XGL_META_VERSION
 */
#define XGL_META_GET(ctx)                                               \
    ({                                                                  \
        void *_data = (void *)(long)(ctx)->data;                        \
        void *_data_meta = (void *)(long)(ctx)->data_meta;              \
        struct xgl_meta *_meta = _data_meta;                            \
        struct xgl_meta *_result = NULL;                                \
        if (_data_meta + sizeof(struct xgl_meta) <= _data &&            \
            _meta->version == XGL_META_VERSION)                         \
            _result = _meta;                                            \
        _result;                                                        \
    })

/*
 * XGL_META_ALLOC(ctx) - Allocate metadata in XDP headroom.
 *
 * Must be called by the root/entry node before any other node
 * can use XGL_META_GET().
 *
 * Returns: pointer to zero-initialized xgl_meta with version set,
 *          or NULL on failure.
 *
 * Preconditions:
 *   - ctx is a valid xdp_md pointer
 *
 * Postconditions:
 *   - headroom is adjusted by sizeof(struct xgl_meta)
 *   - all fields are zero-initialized except version
 *   - version is set to XGL_META_VERSION
 *
 * INTERFACE REQUIREMENT (FM-META-02):
 *   The network interface driver MUST support bpf_xdp_adjust_meta().
 *   If the driver does not support it, this macro returns NULL and
 *   the root node should return XDP_DROP (or XDP_PASS to skip the
 *   pipeline).
 *
 *   Known drivers that support adjust_meta:
 *     - veth (since kernel 4.15)
 *     - mlx5 (Mellanox ConnectX-4+)
 *     - i40e (Intel XL710+)
 *     - ice (Intel E800+)
 *     - bnxt (Broadcom NetXtreme)
 *
 *   Known drivers that do NOT support adjust_meta:
 *     - loopback (lo)
 *     - virtio_net (unless VIRTIO_NET_F_HASH negotiated, kernel 6.3+)
 *     - tun/tap
 *
 *   The root node (xgl_dispatch) handles this by checking the return
 *   and falling back to XDP_DROP with an error counter increment.
 *   This is a controlled failure visible in stats (FM-DISP-01).
 */
#define XGL_META_ALLOC(ctx)                                             \
    ({                                                                  \
        struct xgl_meta *_meta = NULL;                                  \
        if (bpf_xdp_adjust_meta(ctx,                                    \
                -(int)sizeof(struct xgl_meta)) == 0) {                  \
            void *_data = (void *)(long)(ctx)->data;                    \
            void *_data_meta = (void *)(long)(ctx)->data_meta;          \
            _meta = _data_meta;                                         \
            if (_data_meta + sizeof(struct xgl_meta) <= _data) {        \
                __builtin_memset(_meta, 0, sizeof(struct xgl_meta));    \
                _meta->version = XGL_META_VERSION;                      \
            } else {                                                    \
                _meta = NULL;                                           \
            }                                                           \
        }                                                               \
        _meta;                                                          \
    })

/*
 * XGL_NEXT(ctx, prog_array, node_id) - Tail-call to the next node.
 *
 * Delegates to EGL_NEXT from ebpf-graph-lib.
 *
 * This call does not return on success. If it returns, the tail call
 * failed (e.g., invalid node_id or missing program).
 *
 * Preconditions:
 *   - ctx is a valid xdp_md pointer
 *   - prog_array is a BPF_MAP_TYPE_PROG_ARRAY
 *   - node_id < EGL_DEFAULT_MAX_NODES
 */
#define XGL_NEXT(ctx, prog_array, node_id) \
    EGL_NEXT(ctx, prog_array, node_id)

/*
 * XGL_NEXT_SAFE(ctx, prog_array, node_id, stats_map, my_id) -
 * Bounds-checked tail call (FM-META-06).
 *
 * Validates node_id < EGL_DEFAULT_MAX_NODES before tail-calling.
 * If out of range, increments the error counter for this node and
 * returns XDP_DROP.
 *
 * Use this instead of XGL_NEXT when the node_id comes from packet
 * data (e.g., meta->next_node) rather than a compile-time constant.
 *
 * Usage:
 *   XGL_NEXT_SAFE(ctx, egl_prog_array, meta->next_node,
 *                 egl_node_stats, MY_NODE_ID);
 *   // fallback if tail call fails
 *   return XDP_DROP;
 */
#define XGL_NEXT_SAFE(ctx, prog_array, node_id, stats_map, my_id)   \
    do {                                                            \
        __u32 _nid = (node_id);                                     \
        if (_nid >= EGL_DEFAULT_MAX_NODES) {                        \
            EGL_STATS_INC_ERROR(stats_map, my_id);                  \
            return XDP_DROP;                                        \
        }                                                           \
        EGL_NEXT(ctx, prog_array, _nid);                            \
    } while (0)

/*
 * XGL_SCRATCH_AS(meta, type) - Access scratch as a typed struct.
 *
 * Returns a pointer to the scratch area cast to the given type.
 * The caller MUST ensure sizeof(type) <= XGL_SCRATCH_SIZE (32 bytes).
 * See xgl_meta.h scratch ownership rules (FM-META-05).
 *
 * Usage:
 *   struct my_scratch { __u16 vlan_id; __u8 priority; };
 *   struct my_scratch *s = XGL_SCRATCH_AS(meta, struct my_scratch);
 */
#define XGL_SCRATCH_AS(meta, type)                              \
    ({                                                          \
        _Static_assert(sizeof(type) <= XGL_SCRATCH_SIZE,        \
            "scratch type exceeds XGL_SCRATCH_SIZE");            \
        (type *)((meta)->scratch);                              \
    })

/* Terminal actions */
#define XGL_DROP()  return XDP_DROP
#define XGL_PASS()  return XDP_PASS

#endif /* XGL_NODE_H */
