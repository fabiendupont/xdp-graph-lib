/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * xgl_check — deterministic static validation of an XDP graph.
 *
 * Pure function of the spec: fixed iteration order, no allocation,
 * no syscalls, no environment access.  Findings are sorted
 * (severity desc, code asc, message asc) so the output is stable.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "xgl/xgl_check.h"

/* ------------------------------------------------------------------ */
/* Finding collection                                                  */
/* ------------------------------------------------------------------ */

struct xgl_check_ctx {
    struct xgl_check_finding *out;
    int cap;
    int count;
    bool truncated;
};

static void xgl_check_add(struct xgl_check_ctx *ctx,
                          enum xgl_check_code code,
                          enum xgl_check_severity sev,
                          const char *fmt, ...)
{
    va_list ap;
    struct xgl_check_finding *f;

    if (ctx->count >= ctx->cap) {
        ctx->truncated = true;
        return;
    }

    f = &ctx->out[ctx->count];
    f->code = code;
    f->severity = sev;
    va_start(ap, fmt);
    (void)vsnprintf(f->message, sizeof(f->message), fmt, ap);
    va_end(ap);
    ctx->count++;
}

/* ------------------------------------------------------------------ */
/* Deterministic sort of findings                                      */
/* ------------------------------------------------------------------ */

static bool xgl_check_finding_before(const struct xgl_check_finding *a,
                                     const struct xgl_check_finding *b)
{
    if (a->severity != b->severity)
        return a->severity > b->severity;
    if (a->code != b->code)
        return a->code < b->code;
    return strcmp(a->message, b->message) < 0;
}

static void xgl_check_sort(struct xgl_check_finding *f, int n)
{
    int i, j;
    struct xgl_check_finding key;

    for (i = 1; i < n; i++) {
        key = f[i];
        j = i - 1;
        while (j >= 0 && xgl_check_finding_before(&key, &f[j])) {
            f[j + 1] = f[j];
            j--;
        }
        f[j + 1] = key;
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int xgl_check_find_node(const struct xgl_check_spec *spec, int index)
{
    int i;

    for (i = 0; i < spec->n_nodes; i++)
        if (spec->nodes[i].index == index)
            return i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Structural checks                                                   */
/* ------------------------------------------------------------------ */

static void check_spec_sanity(const struct xgl_check_spec *spec,
                              struct xgl_check_ctx *ctx)
{
    if (spec->n_nodes <= 0) {
        xgl_check_add(ctx, XGL_CHECK_E_NO_NODES, XGL_CHECK_SEV_ERROR,
                      "spec has no nodes");
        return;
    }

    if (spec->max_nodes < 1 || spec->max_nodes > XGL_CHECK_MAX_NODES) {
        xgl_check_add(ctx, XGL_CHECK_E_MAX_NODES, XGL_CHECK_SEV_ERROR,
                      "max_nodes=%d out of range [1,%d]",
                      spec->max_nodes, XGL_CHECK_MAX_NODES);
    }

    if (xgl_check_find_node(spec, spec->root_index) < 0) {
        xgl_check_add(ctx, XGL_CHECK_E_ROOT_MISSING, XGL_CHECK_SEV_ERROR,
                      "root index %d is not a node", spec->root_index);
    }
}

static void check_nodes(const struct xgl_check_spec *spec,
                        struct xgl_check_ctx *ctx)
{
    int i, j;

    for (i = 0; i < spec->n_nodes; i++) {
        const struct xgl_check_node *n = &spec->nodes[i];

        if (n->index < 0) {
            xgl_check_add(ctx, XGL_CHECK_E_INDEX_NEG, XGL_CHECK_SEV_ERROR,
                          "node '%s' has negative index %d",
                          n->name, n->index);
            continue;
        }
        if (spec->max_nodes >= 1 && n->index >= spec->max_nodes) {
            xgl_check_add(ctx, XGL_CHECK_E_INDEX_RANGE, XGL_CHECK_SEV_ERROR,
                          "node '%s' index %d >= max_nodes %d",
                          n->name, n->index, spec->max_nodes);
        }
        /* Duplicate detection: compare only with earlier nodes so
         * each pair is reported once. */
        for (j = 0; j < i; j++) {
            if (spec->nodes[j].index == n->index) {
                xgl_check_add(ctx, XGL_CHECK_E_INDEX_DUP,
                              XGL_CHECK_SEV_ERROR,
                              "index %d used by '%s' and '%s'",
                              n->index, spec->nodes[j].name, n->name);
            }
        }
        if (n->stateful) {
            xgl_check_add(ctx, XGL_CHECK_W_STATEFUL, XGL_CHECK_SEV_WARNING,
                          "node '%s' is stateful (per-flow state; "
                          "review determinism impact)", n->name);
        }
    }
}

static void check_edges(const struct xgl_check_spec *spec,
                        struct xgl_check_ctx *ctx)
{
    int i;

    for (i = 0; i < spec->n_edges; i++) {
        const struct xgl_check_edge *e = &spec->edges[i];

        if (xgl_check_find_node(spec, e->from) < 0 ||
            xgl_check_find_node(spec, e->to) < 0) {
            xgl_check_add(ctx, XGL_CHECK_E_EDGE_ENDPOINT, XGL_CHECK_SEV_ERROR,
                          "edge %d->%d references unknown node",
                          e->from, e->to);
        }
        if (e->from == e->to) {
            xgl_check_add(ctx, XGL_CHECK_E_EDGE_SELF, XGL_CHECK_SEV_ERROR,
                          "self-loop on index %d", e->from);
        }
    }
}

/*
 * Cycle detection: iterative DFS with a 3-colour marking.
 * node_color[] is indexed by node *slot* (0..n_nodes-1).
 * Deterministic: visits edges in spec order.
 */
static void check_cycles(const struct xgl_check_spec *spec,
                         struct xgl_check_ctx *ctx)
{
    /* 0 = white (unvisited), 1 = grey (on stack), 2 = black (done) */
    unsigned char color[XGL_CHECK_MAX_NODES];
    int stack[XGL_CHECK_MAX_NODES];
    int edge_pos[XGL_CHECK_MAX_NODES];  /* next edge to explore per slot */
    int top, i, slot;

    memset(color, 0, sizeof(color));

    for (slot = 0; slot < spec->n_nodes; slot++) {
        if (color[slot] != 0)
            continue;

        top = 0;
        stack[0] = slot;
        edge_pos[slot] = 0;
        color[slot] = 1;

        while (top >= 0) {
            int cur = stack[top];
            int next = -1;
            int e;

            /* find next unexplored edge out of cur */
            for (e = edge_pos[cur]; e < spec->n_edges; e++) {
                int dst;

                if (spec->edges[e].from != spec->nodes[cur].index)
                    continue;
                edge_pos[cur] = (int)(e + 1);

                dst = xgl_check_find_node(spec, spec->edges[e].to);
                if (dst < 0)
                    continue;   /* reported by check_edges */
                if (color[dst] == 1) {
                    xgl_check_add(ctx, XGL_CHECK_E_CYCLE,
                                  XGL_CHECK_SEV_ERROR,
                                  "cycle via edge %d->%d",
                                  spec->edges[e].from, spec->edges[e].to);
                    continue;
                }
                if (color[dst] == 0) {
                    next = dst;
                    break;
                }
            }
            if (edge_pos[cur] >= spec->n_edges)
                edge_pos[cur] = spec->n_edges;

            if (next >= 0) {
                top++;
                stack[top] = next;
                edge_pos[next] = 0;
                color[next] = 1;
            } else {
                color[cur] = 2;
                top--;
            }
        }
    }

    (void)i;
}

/*
 * Reachability: BFS from the root over declared edges.
 * The queue holds node slots; visited[] indexed by slot.
 */
static void check_reachability(const struct xgl_check_spec *spec,
                               struct xgl_check_ctx *ctx)
{
    bool visited[XGL_CHECK_MAX_NODES];
    int queue[XGL_CHECK_MAX_NODES];
    int head = 0, tail = 0;
    int root_slot, i;

    memset(visited, 0, sizeof(visited));

    root_slot = xgl_check_find_node(spec, spec->root_index);
    if (root_slot < 0)
        return;     /* reported by check_spec_sanity */

    visited[root_slot] = true;
    queue[tail++] = root_slot;

    while (head < tail) {
        int cur = queue[head++];

        for (i = 0; i < spec->n_edges; i++) {
            int dst;

            if (spec->edges[i].from != spec->nodes[cur].index)
                continue;
            dst = xgl_check_find_node(spec, spec->edges[i].to);
            if (dst < 0)
                continue;
            if (!visited[dst]) {
                visited[dst] = true;
                if (tail < XGL_CHECK_MAX_NODES)
                    queue[tail++] = dst;
            }
        }
    }

    for (i = 0; i < spec->n_nodes; i++) {
        if (!visited[i]) {
            xgl_check_add(ctx, XGL_CHECK_E_UNREACHABLE, XGL_CHECK_SEV_ERROR,
                          "node '%s' (index %d) not reachable from root",
                          spec->nodes[i].name, spec->nodes[i].index);
        }
    }
}

/* ------------------------------------------------------------------ */
/* XSK binding checks                                                  */
/* ------------------------------------------------------------------ */

static void check_xsks(const struct xgl_check_spec *spec,
                       struct xgl_check_ctx *ctx)
{
    int i, j;

    for (i = 0; i < spec->n_xsks; i++) {
        const struct xgl_check_xsk *x = &spec->xsks[i];

        if (x->queue_id < 0) {
            xgl_check_add(ctx, XGL_CHECK_E_QUEUE_NEG, XGL_CHECK_SEV_ERROR,
                          "xsk on '%s' has negative queue_id %d",
                          x->ifname, x->queue_id);
        }
        if (x->n_queues >= 0 && x->queue_id >= x->n_queues) {
            xgl_check_add(ctx, XGL_CHECK_E_QUEUE_RANGE, XGL_CHECK_SEV_ERROR,
                          "xsk on '%s' queue_id %d >= n_queues %d",
                          x->ifname, x->queue_id, x->n_queues);
        }
        if (!x->zerocopy) {
            xgl_check_add(ctx, XGL_CHECK_W_NO_ZEROCOPY, XGL_CHECK_SEV_WARNING,
                          "xsk on '%s' queue %d does not request zero-copy",
                          x->ifname, x->queue_id);
        }
        /* One consumer per (ifname, queue): the core dedication
         * invariant.  Each pair reported once. */
        for (j = 0; j < i; j++) {
            if (strcmp(spec->xsks[j].ifname, x->ifname) == 0 &&
                spec->xsks[j].queue_id == x->queue_id) {
                xgl_check_add(ctx, XGL_CHECK_E_QUEUE_DUP, XGL_CHECK_SEV_ERROR,
                              "queue '%s:%d' has more than one consumer",
                              x->ifname, x->queue_id);
            }
        }

        /* Resource dedication: one IRQ per queue, one CPU per
         * queue.  Each pair reported once. */
        for (j = 0; j < i; j++) {
            const struct xgl_check_xsk *y = &spec->xsks[j];

            if (x->irq >= 0 && x->irq == y->irq) {
                xgl_check_add(ctx, XGL_CHECK_E_IRQ_DUP, XGL_CHECK_SEV_ERROR,
                              "irq %d shared by '%s:%d' and '%s:%d'",
                              x->irq, y->ifname, y->queue_id,
                              x->ifname, x->queue_id);
            }
            if (x->cpu >= 0 && x->cpu == y->cpu) {
                xgl_check_add(ctx, XGL_CHECK_E_CPU_DUP, XGL_CHECK_SEV_ERROR,
                              "cpu %d shared by '%s:%d' and '%s:%d'",
                              x->cpu, y->ifname, y->queue_id,
                              x->ifname, x->queue_id);
            }
        }

        /* NUMA consistency: queue and its dedicated CPU should sit
         * on the same node (jitter, not correctness — warning). */
        if (x->numa_node >= 0 && x->cpu_numa_node >= 0 &&
            x->numa_node != x->cpu_numa_node) {
            xgl_check_add(ctx, XGL_CHECK_W_NUMA_MISMATCH,
                          XGL_CHECK_SEV_WARNING,
                          "'%s:%d' queue on NUMA %d but cpu %d on NUMA %d",
                          x->ifname, x->queue_id, x->numa_node,
                          x->cpu, x->cpu_numa_node);
        }

        /* Neither CPU nor IRQ dedicated: determinism not attempted. */
        if (x->cpu < 0 && x->irq < 0) {
            xgl_check_add(ctx, XGL_CHECK_W_NO_DEDICATION,
                          XGL_CHECK_SEV_WARNING,
                          "'%s:%d' has no dedicated cpu or irq",
                          x->ifname, x->queue_id);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Filter checks                                                       */
/* ------------------------------------------------------------------ */

static void check_filters(const struct xgl_check_spec *spec,
                          struct xgl_check_ctx *ctx)
{
    int i, j;

    for (i = 0; i < spec->n_filters; i++) {
        const struct xgl_check_filter *f = &spec->filters[i];
        bool has_xsk = false;

        for (j = 0; j < spec->n_xsks; j++) {
            if (strcmp(spec->xsks[j].ifname, f->ifname) == 0 &&
                spec->xsks[j].queue_id == f->queue_id) {
                has_xsk = true;
                break;
            }
        }
        if (!has_xsk) {
            xgl_check_add(ctx, XGL_CHECK_E_FILTER_NO_XSK,
                          XGL_CHECK_SEV_ERROR,
                          "filter '%s' queue %d has no XSK binding",
                          f->ifname, f->queue_id);
        }

        if (f->ethertype < XGL_CHECK_ETYPE_MIN) {
            xgl_check_add(ctx, XGL_CHECK_E_ETYPE_RANGE, XGL_CHECK_SEV_ERROR,
                          "ethertype 0x%04x out of range on '%s' queue %d",
                          f->ethertype, f->ifname, f->queue_id);
        }

        /* Determinism invariant: on one interface, a given ethertype
         * must select exactly one queue. */
        for (j = 0; j < i; j++) {
            const struct xgl_check_filter *g = &spec->filters[j];

            if (strcmp(g->ifname, f->ifname) != 0)
                continue;
            if (g->queue_id == f->queue_id && g->ethertype == f->ethertype) {
                xgl_check_add(ctx, XGL_CHECK_E_FILTER_DUP,
                              XGL_CHECK_SEV_ERROR,
                              "duplicate filter 0x%04x on '%s' queue %d",
                              f->ethertype, f->ifname, f->queue_id);
            } else if (g->queue_id != f->queue_id &&
                       g->ethertype == f->ethertype) {
                xgl_check_add(ctx, XGL_CHECK_E_FILTER_OVERLAP,
                              XGL_CHECK_SEV_ERROR,
                              "ethertype 0x%04x matches queues %d and %d "
                              "on '%s' (ambiguous path)",
                              f->ethertype, g->queue_id, f->queue_id,
                              f->ifname);
            }
        }
    }
}


/* ------------------------------------------------------------------ */
/* Named-exit binding checks                                           */
/* ------------------------------------------------------------------ */

static void check_exits(const struct xgl_check_spec *spec,
                        struct xgl_check_ctx *ctx)
{
    int i, j;

    for (i = 0; i < spec->n_exits; i++) {
        const struct xgl_check_exit *e = &spec->exits[i];
        int bound = 0;

        for (j = 0; j < spec->n_bindings; j++) {
            const struct xgl_check_binding *b = &spec->bindings[j];

            if (strcmp(b->prog, e->prog) != 0 ||
                strcmp(b->exit_name, e->exit_name) != 0)
                continue;
            bound++;
            if (bound == 1) {
                if (b->slot < 0 ||
                    (spec->max_nodes >= 1 && b->slot >= spec->max_nodes)) {
                    xgl_check_add(ctx, XGL_CHECK_E_BIND_SLOT,
                                  XGL_CHECK_SEV_ERROR,
                                  "exit '%s/%s' bound to slot %d out of range",
                                  e->prog, e->exit_name, b->slot);
                }
            } else {
                xgl_check_add(ctx, XGL_CHECK_E_BIND_DUP, XGL_CHECK_SEV_ERROR,
                              "exit '%s/%s' has %d bindings",
                              e->prog, e->exit_name, bound);
            }
        }

        if (bound == 0) {
            xgl_check_add(ctx, XGL_CHECK_E_EXIT_UNBOUND, XGL_CHECK_SEV_ERROR,
                          "exit '%s/%s' declared but not bound "
                          "(add_node would reject with -ENOENT)",
                          e->prog, e->exit_name);
        }
    }

    for (i = 0; i < spec->n_bindings; i++) {
        const struct xgl_check_binding *b = &spec->bindings[i];
        int declared = 0;

        for (j = 0; j < spec->n_exits; j++) {
            if (strcmp(spec->exits[j].prog, b->prog) == 0 &&
                strcmp(spec->exits[j].exit_name, b->exit_name) == 0) {
                declared = 1;
                break;
            }
        }
        if (!declared) {
            xgl_check_add(ctx, XGL_CHECK_E_BIND_UNKNOWN, XGL_CHECK_SEV_ERROR,
                          "binding '%s/%s' -> slot %d references an "
                          "undeclared exit",
                          b->prog, b->exit_name, b->slot);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int xgl_check_validate(const struct xgl_check_spec *spec,
                       struct xgl_check_finding *findings,
                       int max_findings)
{
    struct xgl_check_ctx ctx;

    if (spec == NULL)
        return -1;

    ctx.out = findings;
    ctx.cap = (findings != NULL) ? max_findings : 0;
    ctx.count = 0;
    ctx.truncated = false;

    if (ctx.cap < 0)
        ctx.cap = 0;

    check_spec_sanity(spec, &ctx);
    if (spec->n_nodes > 0) {
        check_nodes(spec, &ctx);
        check_edges(spec, &ctx);
        check_cycles(spec, &ctx);
        check_reachability(spec, &ctx);
    }
    check_xsks(spec, &ctx);
    check_filters(spec, &ctx);
    check_exits(spec, &ctx);

    if (ctx.truncated && ctx.count < ctx.cap) {
        xgl_check_add(&ctx, XGL_CHECK_W_TRUNCATED, XGL_CHECK_SEV_WARNING,
                      "findings truncated (%d shown)", ctx.count);
    }

    xgl_check_sort(findings, ctx.count);
    return ctx.count;
}

const char *xgl_check_code_str(enum xgl_check_code code)
{
    switch (code) {
    case XGL_CHECK_OK:               return "OK";
    case XGL_CHECK_E_NO_NODES:       return "E_NO_NODES";
    case XGL_CHECK_E_MAX_NODES:      return "E_MAX_NODES";
    case XGL_CHECK_E_ROOT_MISSING:   return "E_ROOT_MISSING";
    case XGL_CHECK_E_INDEX_NEG:      return "E_INDEX_NEG";
    case XGL_CHECK_E_INDEX_RANGE:    return "E_INDEX_RANGE";
    case XGL_CHECK_E_INDEX_DUP:      return "E_INDEX_DUP";
    case XGL_CHECK_E_EDGE_ENDPOINT:  return "E_EDGE_ENDPOINT";
    case XGL_CHECK_E_EDGE_SELF:      return "E_EDGE_SELF";
    case XGL_CHECK_E_CYCLE:          return "E_CYCLE";
    case XGL_CHECK_E_UNREACHABLE:    return "E_UNREACHABLE";
    case XGL_CHECK_E_QUEUE_NEG:      return "E_QUEUE_NEG";
    case XGL_CHECK_E_QUEUE_RANGE:    return "E_QUEUE_RANGE";
    case XGL_CHECK_E_QUEUE_DUP:      return "E_QUEUE_DUP";
    case XGL_CHECK_E_FILTER_NO_XSK:  return "E_FILTER_NO_XSK";
    case XGL_CHECK_E_ETYPE_RANGE:    return "E_ETYPE_RANGE";
    case XGL_CHECK_E_FILTER_DUP:     return "E_FILTER_DUP";
    case XGL_CHECK_E_FILTER_OVERLAP: return "E_FILTER_OVERLAP";
    case XGL_CHECK_E_IRQ_DUP:        return "E_IRQ_DUP";
    case XGL_CHECK_E_CPU_DUP:        return "E_CPU_DUP";
    case XGL_CHECK_E_EXIT_UNBOUND:   return "E_EXIT_UNBOUND";
    case XGL_CHECK_E_BIND_UNKNOWN:   return "E_BIND_UNKNOWN";
    case XGL_CHECK_E_BIND_SLOT:      return "E_BIND_SLOT";
    case XGL_CHECK_E_BIND_DUP:       return "E_BIND_DUP";
    case XGL_CHECK_W_STATEFUL:       return "W_STATEFUL";
    case XGL_CHECK_W_NO_ZEROCOPY:    return "W_NO_ZEROCOPY";
    case XGL_CHECK_W_NUMA_MISMATCH:  return "W_NUMA_MISMATCH";
    case XGL_CHECK_W_NO_DEDICATION:  return "W_NO_DEDICATION";
    case XGL_CHECK_W_TRUNCATED:      return "W_TRUNCATED";
    }
    return "UNKNOWN";
}
