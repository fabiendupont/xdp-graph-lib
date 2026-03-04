/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_STATS_H
#define XGL_STATS_H

#include <egl/egl_stats.h>

/*
 * XDP-specific stats convenience macros.
 *
 * These map packet-oriented terminology (RX/TX) to the generic
 * egl_node_stats fields (in/out). The underlying struct is
 * egl_node_stats — xdp-graph-lib does NOT define its own stats struct.
 */

#ifdef __BPF__

#define XGL_DECLARE_STATS EGL_DECLARE_STATS

#define XGL_STATS_INC_RX(stats_map, node_id, bytes) \
    EGL_STATS_INC_IN(stats_map, node_id, bytes)

#define XGL_STATS_INC_TX(stats_map, node_id, bytes) \
    EGL_STATS_INC_OUT(stats_map, node_id, bytes)

#define XGL_STATS_INC_DROP(stats_map, node_id) \
    EGL_STATS_INC_DROP(stats_map, node_id)

#define XGL_STATS_INC_ERROR(stats_map, node_id) \
    EGL_STATS_INC_ERROR(stats_map, node_id)

#else /* userspace */

/*
 * Userspace stats functions are provided by egl_stats_*.
 * Use egl_stats_read/read_all/reset directly with the egl_graph
 * obtained via xgl_graph_get_egl().
 */

#endif /* __BPF__ */

#endif /* XGL_STATS_H */
