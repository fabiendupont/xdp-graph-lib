/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_GRAPH_H
#define XGL_GRAPH_H

#include <stddef.h>
#include <stdint.h>

#include <egl/egl_graph.h>
#include <xgl/xgl_exits.h>

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

#include <xgl/bpf/xgl_edges.bpf.h>

/*
 * xgl_graph_bind_exit() - Bind a named exit (XGL_EXIT) to a
 * PROG_ARRAY slot.  Must be called before xgl_graph_add_node() for
 * the node declaring the exit; add_node fails with -ENOENT on an
 * unbound exit.  Rebinding the same (node, exit) replaces the slot.
 *
 * This is the grout-style named-successor model with zero-overhead
 * tail calls: the binding is materialized by rewriting the
 * call-site immediate in a patched copy of the object.
 */
int xgl_graph_bind_exit(struct xgl_graph *g, const char *prog_name,
                        const char *exit_name, int slot);

/*
 * xgl_read_exit_decls() - Read the ".xgl.exits" declarations of a
 * BPF object (XGL_EXIT_TAG).  Caller frees.  Returns -ENOENT when
 * the object declares no exits.  For offline checkers and tooling.
 */
int xgl_read_exit_decls(const char *obj_path,
                        struct xgl_exit_meta **out, size_t *n);

/*
 * xgl_graph_read_all_edges() - Read every ".xgl.edges" entry from a
 * BPF object, unfiltered. Caller frees. Returns -ENOENT when the
 * object declares no edges. For offline checkers and tooling.
 */
int xgl_graph_read_all_edges(const char *obj_path,
                             struct xgl_edge_meta **out, size_t *n);

/*
 * xgl_graph_read_edges() - Read a node object's declared tail-call
 * targets from its ".xgl.edges" metadata section.
 *
 * Returns 0 with a malloc'd array of slot targets (caller frees);
 * -ENOENT when the object declares no edges (terminals, or nodes
 * predating XGL_EDGE); negative errno on malformed objects. The
 * sentinel 0xFFFFFFFF marks dynamic dispatch.
 *
 * xgl_graph_add_node() ingests these automatically; this function
 * exists for offline checkers and tooling.
 */
int xgl_graph_read_edges(const char *obj_path, const char *prog_name,
                         uint32_t **out, size_t *n);

/*
 * xgl_graph_set_dynamic_edge_logger() - Callback for nodes that
 * declare dynamic dispatch (XGL_EDGE_DYNAMIC): their tail-call
 * targets cannot be enumerated, so DAG validation covers declared
 * edges only. The callback lets the application log or reject
 * such nodes.
 */
void xgl_graph_set_dynamic_edge_logger(struct xgl_graph *g,
                                       void (*cb)(const char *prog_name));

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
