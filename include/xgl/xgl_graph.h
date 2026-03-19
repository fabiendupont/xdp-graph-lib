/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_GRAPH_H
#define XGL_GRAPH_H

#include <egl/egl_graph.h>

struct xgl_graph;
struct xgl_xsk;

/*
 * xgl_graph_create() - Create an XDP graph instance.
 *
 * Internally creates an egl_graph for generic operations.
 *
 * @name: human-readable name for the graph instance
 * @max_nodes: PROG_ARRAY size (0 = EGL_DEFAULT_MAX_NODES = 256)
 * @return: graph pointer on success, NULL on failure
 */
struct xgl_graph *xgl_graph_create(const char *name, int max_nodes);

/*
 * xgl_graph_create_shared() - Create an XDP graph with a shared PROG_ARRAY.
 *
 * Delegates to egl_graph_create_shared(). If prog_array_pin_path exists,
 * joins the existing PROG_ARRAY; otherwise creates and pins a new one.
 * Enables cross-project composition (multiple XDP projects sharing one
 * PROG_ARRAY for tail calls between them).
 * NULL pin_path behaves like xgl_graph_create().
 */
struct xgl_graph *xgl_graph_create_shared(const char *name, int max_nodes,
                                          const char *prog_array_pin_path);

/*
 * xgl_graph_add_node() - Add a BPF node to the graph.
 *
 * Delegates to egl_graph_add_node.
 */
int xgl_graph_add_node(struct xgl_graph *g, int index,
                       const char *bpf_obj_path, const char *prog_name);

/*
 * xgl_graph_remove_node() - Remove a node from the graph.
 *
 * Delegates to egl_graph_remove_node.
 */
int xgl_graph_remove_node(struct xgl_graph *g, int index);

/*
 * xgl_graph_add_edge() - Declare a directed edge from src to dst.
 *
 * Delegates to egl_graph_add_edge.
 */
int xgl_graph_add_edge(struct xgl_graph *g, int from, int to);

/*
 * xgl_graph_validate_dag() - Validate that the graph is a DAG.
 *
 * Delegates to egl_graph_validate_dag.
 */
int xgl_graph_validate_dag(struct xgl_graph *g);

/*
 * xgl_graph_attach() - Attach root program to a network interface.
 *
 * XDP-SPECIFIC. Uses bpf_xdp_attach() with XDP_FLAGS_DRV_MODE
 * preferred, falls back to XDP_FLAGS_SKB_MODE.
 *
 * Validates DAG before attachment (SSR-WRAP-003).
 *
 * PRECONDITION (FM-NODE-05): The caller is responsible for providing
 * the correct interface name. The library does not validate whether
 * the specified interface is the intended target for the XDP pipeline.
 * Attaching to the wrong interface will process packets on that
 * interface — this is an application-level safety concern.
 *
 * @g: graph instance
 * @ifname: network interface name (e.g., "eth0")
 * @return: 0 on success, negative errno on failure
 */
int xgl_graph_attach(struct xgl_graph *g, const char *ifname);

/*
 * xgl_graph_detach() - Detach XDP from interface.
 *
 * @g: graph instance
 * @ifname: network interface name
 * @return: 0 on success, negative errno on failure
 */
int xgl_graph_detach(struct xgl_graph *g, const char *ifname);

/*
 * xgl_graph_add_tx_port() - Add interface to DEVMAP for XDP_REDIRECT.
 *
 * @g: graph instance
 * @ifname: network interface name
 * @return: 0 on success, negative errno on failure
 */
int xgl_graph_add_tx_port(struct xgl_graph *g, const char *ifname);

/*
 * xgl_graph_create_xsk() - Create and register an AF_XDP socket.
 *
 * The XSK fd is inserted into the XSKMAP at queue_id.
 * Zero-copy is preferred.
 *
 * @g: graph instance
 * @ifname: network interface name
 * @queue_id: NIC RX queue index
 * @return: XSK handle on success, NULL on failure
 */
struct xgl_xsk *xgl_graph_create_xsk(struct xgl_graph *g,
                                      const char *ifname, int queue_id);

/*
 * xgl_graph_destroy() - Detach and clean up the graph.
 */
void xgl_graph_destroy(struct xgl_graph *g);

/*
 * xgl_graph_get_egl() - Access the underlying egl_graph.
 */
struct egl_graph *xgl_graph_get_egl(struct xgl_graph *g);

/*
 * xgl_graph_get_prog_array_fd() - Get the PROG_ARRAY map fd.
 *
 * Delegates to egl_graph_get_prog_array_fd.
 */
int xgl_graph_get_prog_array_fd(struct xgl_graph *g);

/*
 * xgl_graph_get_stats_map_fd() - Get the stats map fd.
 *
 * Delegates to egl_graph_get_stats_fd.
 */
int xgl_graph_get_stats_map_fd(struct xgl_graph *g);

/*
 * xgl_graph_get_map_fd() - Get any pinned map fd by name.
 *
 * Delegates to egl_graph_get_map_fd.
 * Returns fd on success, negative errno on failure.
 */
int xgl_graph_get_map_fd(struct xgl_graph *g, const char *map_name);

#endif /* XGL_GRAPH_H */
