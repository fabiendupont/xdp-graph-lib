/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <egl/egl_graph.h>
#include <egl/egl_loader.h>
#include <egl/egl_reconfig.h>
#include <xgl/xgl_graph.h>
#include <xgl/xgl_xsk.h>

#define XGL_MAX_INTERFACES 16
#define XGL_MAX_XSKS       16
#define XGL_PATH_MAX       256
#define XGL_NAME_MAX       64
#define XGL_XSK_FRAME_SIZE 4096
#define XGL_XSK_NUM_FRAMES 4096

struct xgl_graph {
    struct egl_graph *egl;

    /* Root program info for XDP attachment.
     * Stored when the first node (index 0) is added. */
    char root_obj_path[XGL_PATH_MAX];
    char root_prog_name[XGL_NAME_MAX];

    int attached_ifindices[XGL_MAX_INTERFACES];
    int num_attached;
    int devmap_fd;
    int xskmap_fd;
    struct xgl_xsk *xsks[XGL_MAX_XSKS];
    int num_xsks;
};

struct xgl_graph *
xgl_graph_create(const char *name, int max_nodes)
{
    struct xgl_graph *g;

    if (!name || name[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }

    g = calloc(1, sizeof(*g));
    if (!g)
        return NULL;

    g->egl = egl_graph_create(name, max_nodes);
    if (!g->egl) {
        free(g);
        return NULL;
    }

    g->devmap_fd = -1;
    g->xskmap_fd = -1;

    return g;
}

/*
 * FM-NODE-02: Check BPF program type without fully loading.
 *
 * Opens the ELF, finds the named program, and checks its SEC type.
 * Does NOT call bpf_object__load — avoids the double-load that
 * would occur if we used egl_loader_open (which loads) followed
 * by egl_graph_add_node (which loads again).
 *
 * Returns the program type (BPF_PROG_TYPE_*), or negative errno.
 */
static int
check_prog_type(const char *bpf_obj_path, const char *prog_name)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int type;

    obj = bpf_object__open(bpf_obj_path);
    if (!obj)
        return -errno;

    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        bpf_object__close(obj);
        return -ENOENT;
    }

    type = (int)bpf_program__type(prog);
    bpf_object__close(obj);

    return type;
}

int
xgl_graph_add_node(struct xgl_graph *g, int index,
                   const char *bpf_obj_path, const char *prog_name)
{
    int prog_type;
    int err;

    if (!g)
        return -EINVAL;

    /* FM-NODE-02: Validate XDP type before loading */
    prog_type = check_prog_type(bpf_obj_path, prog_name);
    if (prog_type < 0)
        return prog_type;

    if (prog_type != BPF_PROG_TYPE_XDP)
        return -EINVAL;

    err = egl_graph_add_node(g->egl, index, bpf_obj_path, prog_name);
    if (err)
        return err;

    /* Store root program info for XDP attachment.
     * Convention: index 0 is the root entry point. */
    if (index == 0 || g->root_obj_path[0] == '\0') {
        strncpy(g->root_obj_path, bpf_obj_path,
                XGL_PATH_MAX - 1);
        g->root_obj_path[XGL_PATH_MAX - 1] = '\0';
        strncpy(g->root_prog_name, prog_name,
                XGL_NAME_MAX - 1);
        g->root_prog_name[XGL_NAME_MAX - 1] = '\0';
    }

    return 0;
}

int
xgl_graph_remove_node(struct xgl_graph *g, int index)
{
    if (!g)
        return -EINVAL;

    return egl_graph_remove_node(g->egl, index);
}

int
xgl_graph_add_edge(struct xgl_graph *g, int from, int to)
{
    if (!g)
        return -EINVAL;

    return egl_graph_add_edge(g->egl, from, to);
}

int
xgl_graph_validate_dag(struct xgl_graph *g)
{
    if (!g)
        return -EINVAL;

    return egl_graph_validate_dag(g->egl);
}

int
xgl_graph_attach(struct xgl_graph *g, const char *ifname)
{
    unsigned int ifindex;
    int root_fd;
    int err;

    if (!g || !ifname)
        return -EINVAL;

    /* Validate DAG before attaching (FM-DAG-04) */
    err = xgl_graph_validate_dag(g);
    if (err)
        return err;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -errno;

    /* Use the already-loaded root program fd from egl_graph.
     * This program shares all maps (prog_array, stats, application
     * maps) with the rest of the graph via egl_graph_add_node(). */
    root_fd = egl_graph_get_node_fd(g->egl, 0);
    if (root_fd < 0)
        return root_fd;

    err = bpf_xdp_attach((int)ifindex, root_fd, 0, NULL);
    if (err)
        return err;

    if (g->num_attached < XGL_MAX_INTERFACES) {
        g->attached_ifindices[g->num_attached] = (int)ifindex;
        g->num_attached++;
    }

    return 0;
}

int
xgl_graph_detach(struct xgl_graph *g, const char *ifname)
{
    unsigned int ifindex;

    if (!g || !ifname)
        return -EINVAL;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -errno;

    bpf_xdp_detach((int)ifindex, 0, NULL);

    /* Remove from tracked list */
    for (int i = 0; i < g->num_attached; i++) {
        if (g->attached_ifindices[i] == (int)ifindex) {
            g->attached_ifindices[i] =
                g->attached_ifindices[g->num_attached - 1];
            g->num_attached--;
            break;
        }
    }

    return 0;
}

int
xgl_graph_add_tx_port(struct xgl_graph *g, const char *ifname)
{
    unsigned int ifindex;
    struct bpf_devmap_val val;

    if (!g || !ifname)
        return -EINVAL;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return -errno;

    /* Use the shared pinned tx_ports map from BPF nodes.
     * This is the same map all BPF nodes reference after the
     * generalized map sharing in egl_graph_add_node(). */
    if (g->devmap_fd < 0) {
        g->devmap_fd = egl_graph_get_map_fd(g->egl, "tx_ports");
        if (g->devmap_fd < 0)
            return g->devmap_fd;
    }

    memset(&val, 0, sizeof(val));
    val.ifindex = ifindex;

    __u32 key = ifindex;
    return bpf_map_update_elem(g->devmap_fd, &key, &val, BPF_ANY);
}

struct xgl_xsk *
xgl_graph_create_xsk(struct xgl_graph *g,
                      const char *ifname, int queue_id)
{
    LIBBPF_OPTS(bpf_map_create_opts, opts);
    struct xgl_xsk *xsk;
    int fd;

    if (!g || !ifname || queue_id < 0)
        return NULL;

    if (g->num_xsks >= XGL_MAX_XSKS) {
        errno = ENOMEM;
        return NULL;
    }

    xsk = xgl_xsk_create(ifname, queue_id,
                          XGL_XSK_FRAME_SIZE, XGL_XSK_NUM_FRAMES);
    if (!xsk)
        return NULL;

    /* Lazily create XSKMAP */
    if (g->xskmap_fd < 0) {
        g->xskmap_fd = bpf_map_create(BPF_MAP_TYPE_XSKMAP,
                                       "xgl_xsk_map",
                                       sizeof(__u32),
                                       sizeof(__u32),
                                       4, &opts);
        if (g->xskmap_fd < 0) {
            xgl_xsk_destroy(xsk);
            return NULL;
        }
    }

    /* Insert XSK fd into XSKMAP at queue_id */
    fd = xgl_xsk_get_fd(xsk);
    __u32 key = (__u32)queue_id;
    if (bpf_map_update_elem(g->xskmap_fd, &key, &fd, BPF_ANY) != 0) {
        xgl_xsk_destroy(xsk);
        return NULL;
    }

    g->xsks[g->num_xsks] = xsk;
    g->num_xsks++;

    return xsk;
}

void
xgl_graph_destroy(struct xgl_graph *g)
{
    if (!g)
        return;

    /* Clean up any active reconfiguration state */
    egl_reconfig_abort(g->egl);

    /* Detach from all interfaces */
    for (int i = 0; i < g->num_attached; i++) {
        if (g->attached_ifindices[i] > 0)
            bpf_xdp_detach(g->attached_ifindices[i], 0, NULL);
    }

    /* Destroy AF_XDP sockets */
    for (int i = 0; i < g->num_xsks; i++) {
        if (g->xsks[i])
            xgl_xsk_destroy(g->xsks[i]);
    }

    /* Close DEVMAP and XSKMAP */
    if (g->devmap_fd >= 0)
        close(g->devmap_fd);
    if (g->xskmap_fd >= 0)
        close(g->xskmap_fd);

    /* Destroy the underlying egl_graph */
    egl_graph_destroy(g->egl);

    free(g);
}

struct egl_graph *
xgl_graph_get_egl(struct xgl_graph *g)
{
    if (!g)
        return NULL;
    return g->egl;
}

int
xgl_graph_get_prog_array_fd(struct xgl_graph *g)
{
    if (!g)
        return -1;
    return egl_graph_get_prog_array_fd(g->egl);
}

int
xgl_graph_get_stats_map_fd(struct xgl_graph *g)
{
    if (!g)
        return -1;
    return egl_graph_get_stats_fd(g->egl);
}

int
xgl_graph_get_map_fd(struct xgl_graph *g, const char *map_name)
{
    if (!g || !map_name)
        return -EINVAL;
    return egl_graph_get_map_fd(g->egl, map_name);
}
