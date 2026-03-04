/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_LOADER_H
#define XGL_LOADER_H

#include <egl/egl_loader.h>

/*
 * Compatibility layer: xgl_loader_* maps to egl_loader_*.
 *
 * All loader functionality has moved to ebpf-graph-lib.
 * These macros preserve API compatibility for existing users.
 */
#define xgl_bpf_prog          egl_bpf_prog
#define xgl_loader_open        egl_loader_open
#define xgl_loader_get_prog_fd egl_loader_get_prog_fd
#define xgl_loader_pin_maps    egl_loader_pin_maps
#define xgl_loader_reuse_maps  egl_loader_reuse_maps
#define xgl_loader_close       egl_loader_close

#endif /* XGL_LOADER_H */
