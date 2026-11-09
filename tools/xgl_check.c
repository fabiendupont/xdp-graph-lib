/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * xgl_check — CLI for deterministic static validation of an XDP
 * graph specification.
 *
 * Reads a line-based spec from a file (or stdin) and validates it
 * with xgl_check_validate().  No kernel or environment access.
 *
 * Spec format (one directive per line, '#' starts a comment):
 *
 *   graph <name> <max_nodes> <root_index>
 *   node <index> <name> [stateful]
 *   edge <from> <to>
 *   xsk <ifname> <queue_id> <n_queues> [zerocopy]
 *   filter <ifname> <queue_id> <ethertype>     (ethertype: 0xXXXX)
 *
 * Exit codes: 0 = no errors (warnings allowed), 1 = validation
 * errors, 2 = usage or parse error.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xgl/xgl_check.h"

static int parse_line(char *line, int lineno, struct xgl_check_spec *spec)
{
    char directive[16];
    int consumed = 0;
    int n;

    /* strip comment */
    char *hash = strchr(line, '#');
    if (hash != NULL)
        *hash = '\0';

    /* skip blank lines */
    n = sscanf(line, " %15s%n", directive, &consumed);
    if (n != 1)
        return 0;

    if (strcmp(directive, "graph") == 0) {
        char name[XGL_CHECK_NAME_LEN];
        int max_nodes, root;

        if (sscanf(line + consumed, " %31s %d %d", name, &max_nodes,
                   &root) != 3) {
            fprintf(stderr, "line %d: graph needs <name> <max_nodes> "
                    "<root_index>\n", lineno);
            return -1;
        }
        (void)snprintf(spec->name, sizeof(spec->name), "%s", name);
        spec->max_nodes = max_nodes;
        spec->root_index = root;
        return 0;
    }

    if (strcmp(directive, "node") == 0) {
        char name[XGL_CHECK_NAME_LEN];
        char extra[16] = {0};
        int index;

        if (sscanf(line + consumed, " %d %31s %15s", &index, name,
                   extra) >= 2) {
            if (spec->n_nodes >= XGL_CHECK_MAX_NODES) {
                fprintf(stderr, "line %d: too many nodes\n", lineno);
                return -1;
            }
            spec->nodes[spec->n_nodes].index = index;
            (void)snprintf(spec->nodes[spec->n_nodes].name,
                           sizeof(spec->nodes[spec->n_nodes].name), "%s",
                           name);
            spec->nodes[spec->n_nodes].stateful =
                (strcmp(extra, "stateful") == 0);
            spec->n_nodes++;
            return 0;
        }
        fprintf(stderr, "line %d: node needs <index> <name> "
                "[stateful]\n", lineno);
        return -1;
    }

    if (strcmp(directive, "edge") == 0) {
        int from, to;

        if (sscanf(line + consumed, " %d %d", &from, &to) != 2) {
            fprintf(stderr, "line %d: edge needs <from> <to>\n", lineno);
            return -1;
        }
        if (spec->n_edges >= XGL_CHECK_MAX_EDGES) {
            fprintf(stderr, "line %d: too many edges\n", lineno);
            return -1;
        }
        spec->edges[spec->n_edges].from = from;
        spec->edges[spec->n_edges].to = to;
        spec->n_edges++;
        return 0;
    }

    if (strcmp(directive, "xsk") == 0) {
        char ifname[XGL_CHECK_IFNAME_LEN];
        char extra[16] = {0};
        int queue, nqueues;

        if (sscanf(line + consumed, " %15s %d %d %15s", ifname, &queue,
                   &nqueues, extra) >= 3) {
            if (spec->n_xsks >= XGL_CHECK_MAX_XSKS) {
                fprintf(stderr, "line %d: too many xsk bindings\n", lineno);
                return -1;
            }
            (void)snprintf(spec->xsks[spec->n_xsks].ifname,
                           sizeof(spec->xsks[spec->n_xsks].ifname), "%s",
                           ifname);
            spec->xsks[spec->n_xsks].queue_id = queue;
            spec->xsks[spec->n_xsks].n_queues = nqueues;
            spec->xsks[spec->n_xsks].zerocopy =
                (strcmp(extra, "zerocopy") == 0);
            spec->n_xsks++;
            return 0;
        }
        fprintf(stderr, "line %d: xsk needs <ifname> <queue_id> "
                "<n_queues> [zerocopy]\n", lineno);
        return -1;
    }

    if (strcmp(directive, "filter") == 0) {
        char ifname[XGL_CHECK_IFNAME_LEN];
        int etype;
        int queue;

        if (sscanf(line + consumed, " %15s %d %i", ifname, &queue,
                   &etype) != 3) {
            fprintf(stderr, "line %d: filter needs <ifname> <queue_id> "
                    "<ethertype>\n", lineno);
            return -1;
        }
        if (etype < 0 || etype > 0xFFFF) {
            fprintf(stderr, "line %d: ethertype 0x%x too large\n",
                    lineno, etype);
            return -1;
        }
        if (spec->n_filters >= XGL_CHECK_MAX_FILTERS) {
            fprintf(stderr, "line %d: too many filters\n", lineno);
            return -1;
        }
        (void)snprintf(spec->filters[spec->n_filters].ifname,
                       sizeof(spec->filters[spec->n_filters].ifname), "%s",
                       ifname);
        spec->filters[spec->n_filters].queue_id = queue;
        spec->filters[spec->n_filters].ethertype = (unsigned short)etype;
        spec->n_filters++;
        return 0;
    }

    fprintf(stderr, "line %d: unknown directive '%s'\n", lineno,
            directive);
    return -1;
}

int main(int argc, char **argv)
{
    struct xgl_check_spec spec;
    struct xgl_check_finding findings[XGL_CHECK_MAX_FILTERS +
                                       XGL_CHECK_MAX_NODES];
    FILE *in = stdin;
    char line[512];
    int lineno = 0, count, i, errors = 0, warnings = 0;

    if (argc > 2) {
        fprintf(stderr, "usage: %s [spec-file]\n", argv[0]);
        return 2;
    }
    if (argc == 2) {
        in = fopen(argv[1], "r");
        if (in == NULL) {
            fprintf(stderr, "cannot open %s: %s\n", argv[1],
                    strerror(errno));
            return 2;
        }
    }

    memset(&spec, 0, sizeof(spec));
    spec.max_nodes = -1;    /* force explicit graph directive */

    while (fgets(line, sizeof(line), in) != NULL) {
        lineno++;
        if (parse_line(line, lineno, &spec) != 0) {
            if (in != stdin)
                (void)fclose(in);
            return 2;
        }
    }
    if (in != stdin)
        (void)fclose(in);

    if (spec.max_nodes < 0) {
        fprintf(stderr, "missing 'graph' directive\n");
        return 2;
    }

    count = xgl_check_validate(&spec, findings,
                               (int)(sizeof(findings) /
                                     sizeof(findings[0])));

    for (i = 0; i < count; i++) {
        const char *sev = (findings[i].severity == XGL_CHECK_SEV_ERROR)
                              ? "ERROR" : "WARN";

        printf("%s %s: %s\n", sev, xgl_check_code_str(findings[i].code),
               findings[i].message);
        if (findings[i].severity == XGL_CHECK_SEV_ERROR)
            errors++;
        else if (findings[i].severity == XGL_CHECK_SEV_WARNING)
            warnings++;
    }

    printf("---\n%s: %d nodes, %d edges, %d xsk bindings, %d filters: "
           "%d error(s), %d warning(s)\n",
           spec.name, spec.n_nodes, spec.n_edges, spec.n_xsks,
           spec.n_filters, errors, warnings);

    return (errors > 0) ? 1 : 0;
}
