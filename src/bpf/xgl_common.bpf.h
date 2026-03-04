/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_COMMON_BPF_H
#define XGL_COMMON_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef __BPF__
#define __BPF__
#endif

/* Generic graph infrastructure from ebpf-graph-lib */
#include <egl/bpf/egl_common.bpf.h>

/* XDP-specific includes */
#include <xgl/xgl_meta.h>
#include <xgl/xgl_node.h>
#include <xgl/xgl_scratch.h>
#include <xgl/xgl_stats.h>
#include <xgl/xgl_devmap.h>

/* XDP-specific maps (in addition to egl_prog_array and egl_node_stats) */
XGL_DECLARE_DEVMAP(xgl_tx_ports, 256);
XGL_DECLARE_XSKMAP(xgl_xsk_map, 4);

#endif /* XGL_COMMON_BPF_H */
