/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <egl/egl_graph.h>
#include <egl/egl_loader.h>
#include <egl/egl_reconfig.h>
#include <xgl/xgl_graph.h>
#include <xgl/xgl_xsk.h>

/* internal, from xgl_exits.c */
int ensure_patch_dir(struct xgl_graph *g);
void remove_patch_dir(struct xgl_graph *g);
int xgl_patch_exit_immediates(const char *in_path, const char *out_path,
                              const uint32_t *ids, const uint32_t *slots,
                              size_t n);

#define XGL_MAX_INTERFACES 16
#define XGL_MAX_EXIT_BINDINGS 64
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

    /* Optional callback invoked when a node declares dynamic
     * dispatch (XGL_EDGE_DYNAMIC) — its tail-call targets cannot
     * be enumerated, so the DAG validation covers the declared
     * edges only.  Set via xgl_graph_set_dynamic_edge_logger(). */
    void (*log_edge_dyn_cb)(const char *prog_name);

    /* Named-exit bindings (XGL_EXIT): (prog, exit name) -> slot.
     * Applied by rewriting the call-site immediate in a patched
     * copy of the object at add_node time. */
    struct xgl_exit_binding {
        char prog[XGL_NAME_MAX];
        char exit_name[32];
        int  slot;
    } exit_bindings[XGL_MAX_EXIT_BINDINGS];
    int num_exit_bindings;

    /* Directory holding patched object copies; created lazily,
     * removed on destroy (the loader retains object paths). */
    char patch_dir[XGL_PATH_MAX];
    int patch_dir_created;
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

struct xgl_graph *
xgl_graph_create_shared(const char *name, int max_nodes,
                        const char *prog_array_pin_path)
{
    struct xgl_graph *g;

    if (!name || name[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }

    g = calloc(1, sizeof(*g));
    if (!g)
        return NULL;

    g->egl = egl_graph_create_shared(name, max_nodes,
                                     prog_array_pin_path);
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
    const char *load_path = bpf_obj_path;

    if (!g)
        return -EINVAL;

    /* FM-NODE-02: Validate XDP type before loading */
    prog_type = check_prog_type(bpf_obj_path, prog_name);
    if (prog_type < 0)
        return prog_type;

    if (prog_type != BPF_PROG_TYPE_XDP)
        return -EINVAL;

    /* Named exits: if the object declares XGL_EXIT_TAG exits,
     * every one must have a binding; rewrite the magic immediates
     * to the bound slots in a patched copy and load that. */
    {
        struct xgl_exit_meta *decls = NULL;
        size_t ndecls = 0;

        if (xgl_read_exit_decls(bpf_obj_path, &decls, &ndecls) == 0) {
            uint32_t ids[64], slots[64];
            size_t nbind = 0, i, j;
            char patched[XGL_PATH_MAX + 64];
            static int patch_seq;

            for (i = 0; i < ndecls; i++) {
                const struct xgl_exit_binding *b = NULL;

                for (j = 0; j < (size_t)g->num_exit_bindings; j++) {
                    if (strcmp(g->exit_bindings[j].prog, prog_name) == 0 &&
                        strcmp(g->exit_bindings[j].exit_name,
                               decls[i].name) == 0) {
                        b = &g->exit_bindings[j];
                        break;
                    }
                }
                if (!b) {
                    free(decls);
                    return -ENOENT;  /* unbound exit */
                }
                if (nbind < 64) {
                    ids[nbind] = decls[i].id;
                    slots[nbind] = (uint32_t)b->slot;
                    nbind++;
                }
            }
            free(decls);

            err = ensure_patch_dir(g);
            if (err)
                return err;

            (void)snprintf(patched, sizeof(patched), "%s/%s-%d.o",
                           g->patch_dir, prog_name, patch_seq++);
            err = xgl_patch_exit_immediates(bpf_obj_path, patched,
                                            ids, slots, nbind);
            if (err) {
                unlink(patched);
                return err;
            }
            load_path = patched;
        }
    }

    err = egl_graph_add_node(g->egl, index, load_path, prog_name);
    if (err)
        return err;

    /* Auto-ingest declared tail-call targets from the object's
     * ".xgl.edges" section (see xgl/bpf/xgl_edges.bpf.h). A cycle
     * formed by code-declared edges fails here with -ELOOP —
     * discovered at load time, not runtime. */
    {
        uint32_t *targets = NULL;
        size_t ntargets = 0, i;

        if (xgl_graph_read_edges(bpf_obj_path, prog_name,
                                 &targets, &ntargets) == 0) {
            for (i = 0; i < ntargets; i++) {
                if (targets[i] == 0xFFFFFFFFU) {
                    /* dynamic dispatch: cannot enumerate targets */
                    if (g->log_edge_dyn_cb)
                        g->log_edge_dyn_cb(prog_name);
                    continue;
                }
                err = egl_graph_add_edge_safe(g->egl, index,
                                              (int)targets[i]);
                if (err) {
                    egl_graph_remove_node(g->egl, index);
                    free(targets);
                    return err;
                }
            }
            free(targets);
        }
    }

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
        g->devmap_fd = egl_graph_get_map_fd(g->egl, "xgl_tx_ports");
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

    /* Use the pinned XSKMAP shared by all BPF programs.
     * BPF nodes declare xgl_xsk_map via XGL_DECLARE_XSKMAP() in
     * xgl_common.bpf.h.  The first loaded node creates and pins it.
     * We must use that same map — creating a new one via
     * bpf_map_create() would produce a disconnected map that BPF
     * programs never see, causing every bpf_redirect_map() to drop. */
    if (g->xskmap_fd < 0) {
        g->xskmap_fd = egl_graph_get_map_fd(g->egl, "xgl_xsk_map");
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

    /* Remove patched object copies (loader retained their paths). */
    remove_patch_dir(g);

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

void
xgl_graph_set_dynamic_edge_logger(struct xgl_graph *g,
                                  void (*cb)(const char *prog_name))
{
    if (g)
        g->log_edge_dyn_cb = cb;
}

int
xgl_graph_bind_exit(struct xgl_graph *g, const char *prog_name,
                    const char *exit_name, int slot)
{
    struct xgl_exit_binding *b;
    size_t i;

    if (!g || !prog_name || !exit_name || slot < 0)
        return -EINVAL;

    /* Idempotent: rebinding replaces. */
    for (i = 0; i < (size_t)g->num_exit_bindings; i++) {
        b = &g->exit_bindings[i];
        if (strcmp(b->prog, prog_name) == 0 &&
            strcmp(b->exit_name, exit_name) == 0) {
            b->slot = slot;
            return 0;
        }
    }

    if (g->num_exit_bindings >= XGL_MAX_EXIT_BINDINGS)
        return -ENOSPC;

    b = &g->exit_bindings[g->num_exit_bindings++];
    (void)snprintf(b->prog, sizeof(b->prog), "%s", prog_name);
    (void)snprintf(b->exit_name, sizeof(b->exit_name), "%s", exit_name);
    b->slot = slot;
    return 0;
}

int
ensure_patch_dir(struct xgl_graph *g)
{
    if (g->patch_dir_created)
        return 0;

    (void)snprintf(g->patch_dir, sizeof(g->patch_dir),
                   "/tmp/xgl-patched-%d", getpid());
    if (mkdir(g->patch_dir, 0700) != 0 && errno != EEXIST)
        return -errno;
    g->patch_dir_created = 1;
    return 0;
}

void
remove_patch_dir(struct xgl_graph *g)
{
    DIR *dir;
    struct dirent *ent;

    if (!g->patch_dir_created)
        return;

    dir = opendir(g->patch_dir);
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            char path[1024];
            if (ent->d_name[0] == '.')
                continue;
            if (snprintf(path, sizeof(path), "%s/%s",
                         g->patch_dir, ent->d_name) < (int)sizeof(path))
                unlink(path);
        }
        closedir(dir);
    }
    rmdir(g->patch_dir);
    g->patch_dir_created = 0;
}
