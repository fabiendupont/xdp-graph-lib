/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * xgl_edges — extract declared tail-call targets from BPF objects.
 *
 * Prints one line per declared edge:
 *
 *   <object> <prog> <slot>       (static target)
 *   <object> <prog> dynamic      (XGL_EDGE_DYNAMIC)
 *
 * Intended for offline checkers: feed the output into a graph spec
 * (or xgl_check input) so the validated topology is the one the
 * code actually declares, not just what the loader was told.
 *
 * Exit 0 even when objects declare no edges; 2 on usage or ELF
 * errors.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xgl/bpf/xgl_edges.bpf.h>
#include <xgl/xgl_graph.h>

int main(int argc, char **argv)
{
    int i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <object.bpf.o>...\n", argv[0]);
        return 2;
    }

    for (i = 1; i < argc; i++) {
        struct xgl_edge_meta *entries = NULL;
        size_t n = 0, k;
        int ret = xgl_graph_read_all_edges(argv[i], &entries, &n);

        if (ret == -ENOENT)
            continue;   /* no declared edges — fine */

        if (ret != 0) {
            fprintf(stderr, "%s: %s\n", argv[i], strerror(-ret));
            return 2;
        }

        for (k = 0; k < n; k++) {
            if (entries[k].to == XGL_EDGE_DYNAMIC_SENTINEL)
                printf("%s %s dynamic\n", argv[i], entries[k].prog);
            else
                printf("%s %s %u\n", argv[i], entries[k].prog,
                       entries[k].to);
        }
        free(entries);
    }
    return 0;
}
