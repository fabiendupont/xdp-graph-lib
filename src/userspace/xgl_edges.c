/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * xgl_edges — userspace reader for the ".xgl.edges" metadata section
 * declared by XGL_EDGE()/XGL_EDGE_DYNAMIC() in BPF objects.
 *
 * The section is ignored by the kernel and libbpf; this reader makes
 * the node's declared tail-call targets available to the graph
 * loader (auto-ingestion + cycle detection at add_node time) and to
 * offline checkers (tools/xgl_edges).
 */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

#include <xgl/bpf/xgl_edges.bpf.h>
#include <xgl/xgl_graph.h>

/*
 * xgl_graph_read_all_edges - Read every entry of the ".xgl.edges"
 * section, unfiltered. The caller frees the returned array.
 *
 * Returns 0 on success, -ENOENT when the object declares no edges,
 * negative errno on malformed objects.
 */
int
xgl_graph_read_all_edges(const char *obj_path,
                         struct xgl_edge_meta **out, size_t *n)
{
    Elf *elf = NULL;
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data;
    struct xgl_edge_meta *entries;
    int fd = -1;
    int ret = 0;

    if (!obj_path || !out || !n)
        return -EINVAL;

    *out = NULL;
    *n = 0;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return -ELIBBAD;

    fd = open(obj_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        ret = -ELIBBAD;
        goto out;
    }

    scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        size_t shstrndx;

        if (gelf_getshdr(scn, &shdr) != &shdr)
            continue;
        if (elf_getshdrstrndx(elf, &shstrndx) != 0)
            continue;
        const char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name && strcmp(name, ".xgl.edges") == 0)
            break;
    }
    if (!scn) {
        ret = -ENOENT;
        goto out;
    }

    data = elf_getdata(scn, NULL);
    if (!data || data->d_size == 0 || data->d_size % sizeof(*entries) != 0) {
        ret = -EINVAL;
        goto out;
    }

    entries = malloc(data->d_size);
    if (!entries) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(entries, data->d_buf, data->d_size);

    *out = entries;
    *n = data->d_size / sizeof(*entries);

out:
    if (elf)
        elf_end(elf);
    if (fd >= 0)
        close(fd);
    return ret;
}

/*
 * xgl_graph_read_edges - Read the declared tail-call targets for
 * one program (entries whose prog name does not match are
 * skipped). The sentinel XGL_EDGE_DYNAMIC_SENTINEL marks dynamic
 * dispatch. The caller frees the returned array.
 *
 * Returns 0 on success, -ENOENT when the object declares no edges
 * for this program, negative errno on malformed objects.
 */
int
xgl_graph_read_edges(const char *obj_path, const char *prog_name,
                     uint32_t **out, size_t *n)
{
    struct xgl_edge_meta *entries = NULL;
    size_t count = 0, i, j = 0;
    uint32_t *targets;
    int ret;

    if (!obj_path || !prog_name || !out || !n)
        return -EINVAL;

    *out = NULL;
    *n = 0;

    ret = xgl_graph_read_all_edges(obj_path, &entries, &count);
    if (ret)
        return ret;

    targets = calloc(count, sizeof(*targets));
    if (!targets) {
        free(entries);
        return -ENOMEM;
    }

    for (i = 0; i < count; i++) {
        if (strncmp(entries[i].prog, prog_name,
                    sizeof(entries[i].prog)) == 0)
            targets[j++] = entries[i].to;
    }
    free(entries);

    if (j == 0) {
        free(targets);
        return -ENOENT;
    }

    *out = targets;
    *n = j;
    return 0;
}
