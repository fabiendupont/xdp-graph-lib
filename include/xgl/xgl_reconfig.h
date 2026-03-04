/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_RECONFIG_H
#define XGL_RECONFIG_H

#include <egl/egl_reconfig.h>

/*
 * Compatibility layer: xgl_reconfig_* maps to egl_reconfig_*.
 *
 * All reconfiguration functionality has moved to ebpf-graph-lib.
 * These macros preserve API compatibility for existing users.
 *
 * Note: xgl_reconfig functions now operate on the underlying
 * egl_graph instance. Use xgl_graph_get_egl() to obtain it.
 */
#define xgl_reconfig_begin       egl_reconfig_begin
#define xgl_reconfig_add_node    egl_reconfig_add_node
#define xgl_reconfig_remove_node egl_reconfig_remove_node
#define xgl_reconfig_commit      egl_reconfig_commit
#define xgl_reconfig_abort       egl_reconfig_abort

#endif /* XGL_RECONFIG_H */
