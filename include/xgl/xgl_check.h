/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_CHECK_H
#define XGL_CHECK_H

#include <stdbool.h>

/*
 * xgl_check — deterministic static validation of an XDP graph
 * configuration.
 *
 * The graph-level static check: validates a *declarative* description
 * of an intended XDP graph (nodes, edges, XSK bindings, EtherType
 * filters) against structural and determinism invariants, without
 * touching the kernel, libbpf, or any environment state.
 *
 * Properties:
 *   - Pure function of the spec: same input, same findings, same
 *     order — always.  No syscalls, no clocks, no environment reads.
 *   - No dynamic allocation; bounded, fixed-size state.
 *
 * Intended use: the DRA driver (or any orchestrator) generates the
 * spec from claim parameters, runs xgl_check, and only proceeds to
 * load the graph if validation passes.  The in-kernel BPF verifier
 * remains a runtime assertion; this check is the deterministic gate.
 */

#define XGL_CHECK_MAX_NODES 256
#define XGL_CHECK_MAX_EDGES 512
#define XGL_CHECK_MAX_XSKS 64
#define XGL_CHECK_MAX_FILTERS 256
#define XGL_CHECK_IFNAME_LEN 16
#define XGL_CHECK_NAME_LEN 32
#define XGL_CHECK_MSG_LEN 160

/*
 * IEEE 802 EtherType bounds: values below 0x0600 are length fields,
 * not protocol identifiers.
 */
#define XGL_CHECK_ETYPE_MIN 0x0600u
#define XGL_CHECK_ETYPE_MAX 0xFFFFu

enum xgl_check_severity {
    XGL_CHECK_SEV_OK = 0,
    XGL_CHECK_SEV_WARNING = 1,
    XGL_CHECK_SEV_ERROR = 2,
};

enum xgl_check_code {
    XGL_CHECK_OK = 0,

    /* Spec-level errors */
    XGL_CHECK_E_NO_NODES,       /* empty graph                    */
    XGL_CHECK_E_MAX_NODES,      /* max_nodes out of range         */
    XGL_CHECK_E_ROOT_MISSING,   /* root_index is not a node       */

    /* Node errors */
    XGL_CHECK_E_INDEX_NEG,      /* negative node index            */
    XGL_CHECK_E_INDEX_RANGE,    /* index >= max_nodes             */
    XGL_CHECK_E_INDEX_DUP,      /* duplicate node index           */

    /* Edge errors */
    XGL_CHECK_E_EDGE_ENDPOINT,  /* edge references unknown node   */
    XGL_CHECK_E_EDGE_SELF,      /* self-loop                      */
    XGL_CHECK_E_CYCLE,          /* cycle in the graph             */
    XGL_CHECK_E_UNREACHABLE,    /* node not reachable from root   */

    /* XSK binding errors */
    XGL_CHECK_E_QUEUE_NEG,      /* negative queue id              */
    XGL_CHECK_E_QUEUE_RANGE,    /* queue_id >= n_queues           */
    XGL_CHECK_E_QUEUE_DUP,      /* two consumers on one queue     */

    /* Filter errors */
    XGL_CHECK_E_FILTER_NO_XSK,  /* filter w/o matching XSK bind   */
    XGL_CHECK_E_ETYPE_RANGE,    /* ethertype outside 0x0600..FFFF */
    XGL_CHECK_E_FILTER_DUP,     /* duplicate filter on one queue  */
    XGL_CHECK_E_FILTER_OVERLAP, /* same ethertype, two queues     */

    /* Warnings */
    XGL_CHECK_W_STATEFUL,       /* stateful node in the graph     */
    XGL_CHECK_W_NO_ZEROCOPY,    /* zerocopy not requested         */
    XGL_CHECK_W_TRUNCATED,      /* findings buffer exhausted      */
};

/* One BPF node in the intended graph. */
struct xgl_check_node {
    int index;                          /* PROG_ARRAY slot */
    char name[XGL_CHECK_NAME_LEN];      /* node identifier */
    bool stateful;                      /* node keeps per-flow state */
};

/* One declared tail-call edge (from -> to). */
struct xgl_check_edge {
    int from;
    int to;
};

/*
 * One AF_XDP socket binding: a dedicated consumer of one RX queue.
 * n_queues is the total queue count of the interface as known to the
 * orchestrator (the check does not read sysfs — determinism).
 */
struct xgl_check_xsk {
    char ifname[XGL_CHECK_IFNAME_LEN];
    int queue_id;
    int n_queues;
    bool zerocopy;                      /* zero-copy intended */
};

/*
 * One EtherType filter: frames of this type on (ifname, queue_id)
 * are redirected to the XSK bound to that queue.
 */
struct xgl_check_filter {
    char ifname[XGL_CHECK_IFNAME_LEN];
    int queue_id;
    unsigned short ethertype;
};

/* Declarative description of the entire intended graph. */
struct xgl_check_spec {
    char name[XGL_CHECK_NAME_LEN];
    int max_nodes;                      /* PROG_ARRAY size */
    int root_index;                     /* dispatch root slot */
    struct xgl_check_node nodes[XGL_CHECK_MAX_NODES];
    int n_nodes;
    struct xgl_check_edge edges[XGL_CHECK_MAX_EDGES];
    int n_edges;
    struct xgl_check_xsk xsks[XGL_CHECK_MAX_XSKS];
    int n_xsks;
    struct xgl_check_filter filters[XGL_CHECK_MAX_FILTERS];
    int n_filters;
};

/* One validation finding. */
struct xgl_check_finding {
    enum xgl_check_code code;
    enum xgl_check_severity severity;
    char message[XGL_CHECK_MSG_LEN];
};

/*
 * xgl_check_validate() - Validate a graph spec deterministically.
 *
 * Checks, in order:
 *   1. Spec sanity: non-empty, max_nodes in [1, XGL_CHECK_MAX_NODES],
 *      root node exists.
 *   2. Nodes: index bounds, uniqueness.
 *   3. Edges: endpoints exist, no self-loops, graph is a DAG,
 *      every node reachable from the root.
 *   4. XSK bindings: queue bounds, at most one consumer per
 *      (ifname, queue_id).
 *   5. Filters: matching XSK binding exists, EtherType range,
 *      no duplicate filters, filter sets on the same interface are
 *      pairwise disjoint (a frame matches at most one path — the
 *      core determinism invariant).
 *
 * Findings are sorted deterministically (severity descending, then
 * code, then message).  If the buffer fills, a single
 * XGL_CHECK_W_TRUNCATED finding is emitted.
 *
 * @spec:         graph description (must not be NULL)
 * @findings:     output array (may be NULL if max_findings == 0)
 * @max_findings: capacity of @findings
 *
 * Returns the number of findings written, or -1 if @spec is NULL.
 */
int xgl_check_validate(const struct xgl_check_spec *spec,
                       struct xgl_check_finding *findings,
                       int max_findings);

/* Human-readable finding code name (static string). */
const char *xgl_check_code_str(enum xgl_check_code code);

#endif /* XGL_CHECK_H */
