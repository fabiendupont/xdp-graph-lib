/* SPDX-License-Identifier: BSD-2-Clause */

#define _DEFAULT_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <xdp/xsk.h>

#include <xgl/xgl_xsk.h>

/*
 * Maximum number of packets in a single recv_batch call.
 * Addresses are stored so recv_release_batch does not re-peek.
 */
#define XGL_XSK_MAX_BATCH 64

struct xgl_xsk {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *umem_area;
    __u64 umem_size;

    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    struct xsk_ring_cons rx_ring;
    struct xsk_ring_prod tx_ring;

    __u32 frame_size;
    __u32 num_frames;
    __u64 cur_tx;
    __u32 pending_tx;      /* reserved in tx_ring, not yet submitted */
    __u32 outstanding_tx;  /* submitted to kernel, not yet completed */

    /* Track last received frame for release */
    __u64 last_rx_addr;

    /* Track batch-received addresses for release without re-peek */
    __u64 batch_addrs[XGL_XSK_MAX_BATCH];
    int batch_count;

    bool zerocopy;

    /* Rootless / inherited path: fds received via SCM_RIGHTS.
     * raw_fd >= 0 means this socket was not created here; xsk and umem
     * are NULL and the ring memory is tracked via the _map fields below. */
    int raw_fd;
    void *fill_map;
    void *comp_map;
    void *rx_map;
    void *tx_map;
    __u64 fill_map_size;
    __u64 comp_map_size;
    __u64 rx_map_size;
    __u64 tx_map_size;
};

struct xgl_xsk *
xgl_xsk_create(const char *ifname, int queue_id,
                __u32 frame_size, __u32 num_frames)
{
    struct xgl_xsk *xsk;
    struct xsk_umem_config ucfg;
    struct xsk_socket_config scfg;
    __u32 idx;
    int err;

    if (!ifname || queue_id < 0 || frame_size == 0 || num_frames == 0) {
        errno = EINVAL;
        return NULL;
    }

    /* num_frames must be a power of 2 (libxdp rejects otherwise
     * with an opaque error — validate early with a clear errno) */
    if ((num_frames & (num_frames - 1)) != 0) {
        errno = EINVAL;
        return NULL;
    }

    xsk = calloc(1, sizeof(*xsk));
    if (!xsk)
        return NULL;

    xsk->raw_fd = -1;
    xsk->frame_size = frame_size;
    xsk->num_frames = num_frames;
    xsk->umem_size = (__u64)frame_size * num_frames;

    /* Allocate page-aligned UMEM area */
    xsk->umem_area = mmap(NULL, xsk->umem_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (xsk->umem_area == MAP_FAILED) {
        free(xsk);
        return NULL;
    }

    /* Configure UMEM */
    memset(&ucfg, 0, sizeof(ucfg));
    ucfg.fill_size = num_frames;
    ucfg.comp_size = num_frames;
    ucfg.frame_size = frame_size;
    ucfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;

    err = xsk_umem__create(&xsk->umem, xsk->umem_area,
                           xsk->umem_size,
                           &xsk->fill_ring, &xsk->comp_ring,
                           &ucfg);
    if (err) {
        munmap(xsk->umem_area, xsk->umem_size);
        free(xsk);
        errno = -err;
        return NULL;
    }

    /* Pre-populate fill ring with frame addresses */
    if (xsk_ring_prod__reserve(&xsk->fill_ring, num_frames, &idx)
        != num_frames) {
        xsk_umem__delete(xsk->umem);
        munmap(xsk->umem_area, xsk->umem_size);
        free(xsk);
        errno = ENOMEM;
        return NULL;
    }
    for (__u32 i = 0; i < num_frames; i++)
        *xsk_ring_prod__fill_addr(&xsk->fill_ring, idx + i) =
            (__u64)i * frame_size;
    xsk_ring_prod__submit(&xsk->fill_ring, num_frames);

    /* Configure socket — try XDP_ZEROCOPY (native mode) first */
    memset(&scfg, 0, sizeof(scfg));
    scfg.rx_size = num_frames;
    scfg.tx_size = num_frames;
    scfg.xdp_flags = 0;
    scfg.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

    err = xsk_socket__create(&xsk->xsk, ifname,
                             (__u32)queue_id, xsk->umem,
                             &xsk->rx_ring, &xsk->tx_ring, &scfg);
    if (err == 0) {
        xsk->zerocopy = true;
    } else {
        /* Fall back to XDP_COPY with native mode */
        scfg.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP;
        err = xsk_socket__create(&xsk->xsk, ifname,
                                 (__u32)queue_id, xsk->umem,
                                 &xsk->rx_ring, &xsk->tx_ring, &scfg);
        if (err) {
            /* Final fallback: XDP_COPY with SKB mode for
             * interfaces without native XDP support */
            scfg.xdp_flags = XDP_FLAGS_SKB_MODE;
            scfg.bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP;
            err = xsk_socket__create(&xsk->xsk, ifname,
                                     (__u32)queue_id, xsk->umem,
                                     &xsk->rx_ring, &xsk->tx_ring,
                                     &scfg);
            if (err) {
                xsk_umem__delete(xsk->umem);
                munmap(xsk->umem_area, xsk->umem_size);
                free(xsk);
                errno = -err;
                return NULL;
            }
        }
        xsk->zerocopy = false;
    }

    return xsk;
}

void
xgl_xsk_destroy(struct xgl_xsk *xsk)
{
    if (!xsk)
        return;

    if (xsk->raw_fd >= 0) {
        /* Inherited path: unmap rings we mmap'd, close the fds. */
        if (xsk->fill_map && xsk->fill_map != MAP_FAILED)
            munmap(xsk->fill_map, xsk->fill_map_size);
        if (xsk->comp_map && xsk->comp_map != MAP_FAILED)
            munmap(xsk->comp_map, xsk->comp_map_size);
        if (xsk->rx_map && xsk->rx_map != MAP_FAILED)
            munmap(xsk->rx_map, xsk->rx_map_size);
        if (xsk->tx_map && xsk->tx_map != MAP_FAILED)
            munmap(xsk->tx_map, xsk->tx_map_size);
        if (xsk->umem_area && xsk->umem_area != MAP_FAILED)
            munmap(xsk->umem_area, xsk->umem_size);
        close(xsk->raw_fd);
    } else {
        if (xsk->xsk)
            xsk_socket__delete(xsk->xsk);
        if (xsk->umem)
            xsk_umem__delete(xsk->umem);
        if (xsk->umem_area && xsk->umem_area != MAP_FAILED)
            munmap(xsk->umem_area, xsk->umem_size);
    }

    free(xsk);
}

bool
xgl_xsk_is_zerocopy(const struct xgl_xsk *xsk)
{
    if (!xsk)
        return false;
    return xsk->zerocopy;
}

int
xgl_xsk_recv(struct xgl_xsk *xsk, void **pkt_data, __u32 *pkt_len)
{
    __u32 idx_rx = 0;
    unsigned int rcvd;

    if (!xsk || !pkt_data || !pkt_len)
        return 0;

    rcvd = xsk_ring_cons__peek(&xsk->rx_ring, 1, &idx_rx);
    if (rcvd == 0)
        return 0;

    const struct xdp_desc *desc =
        xsk_ring_cons__rx_desc(&xsk->rx_ring, idx_rx);

    *pkt_data = xsk_umem__get_data(xsk->umem_area, desc->addr);
    *pkt_len = desc->len;
    xsk->last_rx_addr = desc->addr;

    return 1;
}

void
xgl_xsk_recv_release(struct xgl_xsk *xsk)
{
    __u32 idx_fq = 0;

    if (!xsk)
        return;

    /* Release the RX descriptor */
    xsk_ring_cons__release(&xsk->rx_ring, 1);

    /* Return the frame to the fill ring */
    if (xsk_ring_prod__reserve(&xsk->fill_ring, 1, &idx_fq) == 1) {
        *xsk_ring_prod__fill_addr(&xsk->fill_ring, idx_fq) =
            xsk->last_rx_addr;
        xsk_ring_prod__submit(&xsk->fill_ring, 1);
    }
}

void *
xgl_xsk_send_alloc(struct xgl_xsk *xsk, __u32 len)
{
    __u32 idx = 0;
    __u64 addr;

    if (!xsk || len == 0)
        return NULL;

    /* Drain completion ring first */
    __u32 comp_idx = 0;
    unsigned int completed =
        xsk_ring_cons__peek(&xsk->comp_ring, xsk->outstanding_tx,
                            &comp_idx);
    if (completed > 0) {
        xsk_ring_cons__release(&xsk->comp_ring, completed);
        xsk->outstanding_tx -= completed;
    }

    /* Refuse allocation if all frames are in-flight (pending in
     * tx_ring or submitted to kernel).  Without this check, cur_tx
     * wraps into a frame still owned by kernel DMA. */
    if (xsk->pending_tx + xsk->outstanding_tx >= xsk->num_frames)
        return NULL;

    if (xsk_ring_prod__reserve(&xsk->tx_ring, 1, &idx) != 1)
        return NULL;

    addr = xsk->cur_tx * xsk->frame_size;
    xsk->cur_tx = (xsk->cur_tx + 1) % xsk->num_frames;

    struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xsk->tx_ring, idx);
    desc->addr = addr;
    desc->len = len;

    xsk->pending_tx++;

    return xsk_umem__get_data(xsk->umem_area, addr);
}

int
xgl_xsk_send_complete(struct xgl_xsk *xsk)
{
    if (!xsk)
        return -EINVAL;

    if (xsk->pending_tx == 0)
        return 0;

    /* Submit only newly-reserved frames since last complete */
    xsk_ring_prod__submit(&xsk->tx_ring, xsk->pending_tx);
    xsk->outstanding_tx += xsk->pending_tx;
    xsk->pending_tx = 0;

    /* Kick kernel */
    if (xsk_ring_prod__needs_wakeup(&xsk->tx_ring)) {
        ssize_t ret = sendto(xgl_xsk_get_fd(xsk),
                             NULL, 0, MSG_DONTWAIT, NULL, 0);
        if (ret < 0 && errno != EAGAIN && errno != ENOBUFS &&
            errno != EBUSY)
            return -errno;
    }

    return 0;
}

int
xgl_xsk_poll(struct xgl_xsk *xsk, int timeout_ms)
{
    struct pollfd fds;

    if (!xsk)
        return -EINVAL;

    fds.fd = xgl_xsk_get_fd(xsk);
    fds.events = POLLIN | POLLOUT;
    fds.revents = 0;

    return poll(&fds, 1, timeout_ms);
}

int
xgl_xsk_get_fd(const struct xgl_xsk *xsk)
{
    if (!xsk)
        return -1;
    if (xsk->raw_fd >= 0)
        return xsk->raw_fd;
    if (!xsk->xsk)
        return -1;
    return xsk_socket__fd(xsk->xsk);
}

int
xgl_xsk_recv_batch(struct xgl_xsk *xsk,
                    void **pkt_data, __u32 *pkt_lens,
                    int max)
{
    __u32 idx_rx = 0;
    unsigned int rcvd;

    if (!xsk || !pkt_data || !pkt_lens || max <= 0)
        return 0;

    /* Clamp to max batch size so recv_release_batch can use
     * the stored addresses without re-peeking the RX ring */
    if (max > XGL_XSK_MAX_BATCH)
        max = XGL_XSK_MAX_BATCH;

    rcvd = xsk_ring_cons__peek(&xsk->rx_ring, (__u32)max, &idx_rx);
    if (rcvd == 0)
        return 0;

    for (unsigned int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc =
            xsk_ring_cons__rx_desc(&xsk->rx_ring, idx_rx + i);
        pkt_data[i] = xsk_umem__get_data(xsk->umem_area, desc->addr);
        pkt_lens[i] = desc->len;
        xsk->batch_addrs[i] = desc->addr;
    }
    xsk->batch_count = (int)rcvd;

    return (int)rcvd;
}

void
xgl_xsk_recv_release_batch(struct xgl_xsk *xsk, int count)
{
    __u32 idx_fq = 0;
    __u32 n;

    if (!xsk || count <= 0)
        return;

    /* Use the addresses stored by recv_batch instead of re-peeking
     * the RX ring.  Re-peeking is fragile if any other recv call
     * touches the ring between recv_batch and release_batch. */
    n = (__u32)count;
    if (n > (__u32)xsk->batch_count)
        n = (__u32)xsk->batch_count;

    /* Replenish fill ring */
    if (xsk_ring_prod__reserve(&xsk->fill_ring, n, &idx_fq) == n) {
        for (__u32 i = 0; i < n; i++)
            *xsk_ring_prod__fill_addr(&xsk->fill_ring, idx_fq + i) =
                xsk->batch_addrs[i];
        xsk_ring_prod__submit(&xsk->fill_ring, n);
    }

    xsk_ring_cons__release(&xsk->rx_ring, n);
    xsk->batch_count = 0;
}

struct xgl_xsk *
xgl_xsk_inherit(int xsk_fd, int umem_fd, __u32 frame_size, __u32 num_frames)
{
    struct xgl_xsk *xsk;
    struct xdp_mmap_offsets off;
    socklen_t optlen;
    __u32 idx;

    if (xsk_fd < 0 || umem_fd < 0 || frame_size == 0 || num_frames == 0) {
        errno = EINVAL;
        return NULL;
    }

    if ((num_frames & (num_frames - 1)) != 0) {
        errno = EINVAL;
        return NULL;
    }

    xsk = calloc(1, sizeof(*xsk));
    if (!xsk)
        return NULL;

    xsk->raw_fd     = xsk_fd;
    xsk->frame_size = frame_size;
    xsk->num_frames = num_frames;
    xsk->umem_size  = (__u64)frame_size * num_frames;
    xsk->zerocopy   = false; /* unknown from this side; conservative */

    /* Map the UMEM data area from the memfd. */
    xsk->umem_area = mmap(NULL, xsk->umem_size,
                          PROT_READ | PROT_WRITE, MAP_SHARED, umem_fd, 0);
    if (xsk->umem_area == MAP_FAILED) {
        free(xsk);
        return NULL;
    }

    /* Retrieve ring layout from the kernel. */
    optlen = sizeof(off);
    if (getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        munmap(xsk->umem_area, xsk->umem_size);
        free(xsk);
        return NULL;
    }

    /* Fill ring (UMEM fill queue). */
    xsk->fill_map_size = off.fr.desc + (__u64)num_frames * sizeof(__u64);
    xsk->fill_map = mmap(NULL, xsk->fill_map_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         xsk_fd, XDP_UMEM_PGOFF_FILL_RING);
    if (xsk->fill_map == MAP_FAILED)
        goto err_fill;

#define MAP_U32(base, off) ((__u32 *)((uint8_t *)(base) + (off)))
#define MAP_PTR(base, off) ((uint8_t *)(base) + (off))

    xsk->fill_ring.mask     = num_frames - 1;
    xsk->fill_ring.size     = num_frames;
    xsk->fill_ring.producer = MAP_U32(xsk->fill_map, off.fr.producer);
    xsk->fill_ring.consumer = MAP_U32(xsk->fill_map, off.fr.consumer);
    xsk->fill_ring.ring     = MAP_PTR(xsk->fill_map, off.fr.desc);
    xsk->fill_ring.flags    = MAP_U32(xsk->fill_map, off.fr.flags);

    /* Completion ring (UMEM completion queue). */
    xsk->comp_map_size = off.cr.desc + (__u64)num_frames * sizeof(__u64);
    xsk->comp_map = mmap(NULL, xsk->comp_map_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                         xsk_fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (xsk->comp_map == MAP_FAILED)
        goto err_comp;

    xsk->comp_ring.mask     = num_frames - 1;
    xsk->comp_ring.size     = num_frames;
    xsk->comp_ring.producer = MAP_U32(xsk->comp_map, off.cr.producer);
    xsk->comp_ring.consumer = MAP_U32(xsk->comp_map, off.cr.consumer);
    xsk->comp_ring.ring     = MAP_PTR(xsk->comp_map, off.cr.desc);
    xsk->comp_ring.flags    = MAP_U32(xsk->comp_map, off.cr.flags);

    /* RX ring. */
    xsk->rx_map_size = off.rx.desc +
                       (__u64)num_frames * sizeof(struct xdp_desc);
    xsk->rx_map = mmap(NULL, xsk->rx_map_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                       xsk_fd, XDP_PGOFF_RX_RING);
    if (xsk->rx_map == MAP_FAILED)
        goto err_rx;

    xsk->rx_ring.mask     = num_frames - 1;
    xsk->rx_ring.size     = num_frames;
    xsk->rx_ring.producer = MAP_U32(xsk->rx_map, off.rx.producer);
    xsk->rx_ring.consumer = MAP_U32(xsk->rx_map, off.rx.consumer);
    xsk->rx_ring.ring     = MAP_PTR(xsk->rx_map, off.rx.desc);
    xsk->rx_ring.flags    = MAP_U32(xsk->rx_map, off.rx.flags);

    /* TX ring. */
    xsk->tx_map_size = off.tx.desc +
                       (__u64)num_frames * sizeof(struct xdp_desc);
    xsk->tx_map = mmap(NULL, xsk->tx_map_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                       xsk_fd, XDP_PGOFF_TX_RING);
    if (xsk->tx_map == MAP_FAILED)
        goto err_tx;

    xsk->tx_ring.mask     = num_frames - 1;
    xsk->tx_ring.size     = num_frames;
    xsk->tx_ring.producer = MAP_U32(xsk->tx_map, off.tx.producer);
    xsk->tx_ring.consumer = MAP_U32(xsk->tx_map, off.tx.consumer);
    xsk->tx_ring.ring     = MAP_PTR(xsk->tx_map, off.tx.desc);
    xsk->tx_ring.flags    = MAP_U32(xsk->tx_map, off.tx.flags);

#undef MAP_U32
#undef MAP_PTR

    /* Seed the fill ring — the daemon left it empty for us to fill. */
    if (xsk_ring_prod__reserve(&xsk->fill_ring, num_frames, &idx)
        == num_frames) {
        for (__u32 i = 0; i < num_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->fill_ring, idx + i) =
                (__u64)i * frame_size;
        xsk_ring_prod__submit(&xsk->fill_ring, num_frames);
    }

    return xsk;

err_tx:
    munmap(xsk->rx_map, xsk->rx_map_size);
err_rx:
    munmap(xsk->comp_map, xsk->comp_map_size);
err_comp:
    munmap(xsk->fill_map, xsk->fill_map_size);
err_fill:
    munmap(xsk->umem_area, xsk->umem_size);
    free(xsk);
    return NULL;
}
