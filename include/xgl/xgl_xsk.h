/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_XSK_H
#define XGL_XSK_H

#include <stdbool.h>
#include <linux/types.h>

struct xgl_xsk;

/*
 * xgl_xsk_create() - Create an AF_XDP socket with zero-copy preferred.
 *
 * Attempts XDP_ZEROCOPY bind first (NIC DMAs directly into UMEM,
 * no kernel copy). Falls back to XDP_COPY if driver doesn't support it.
 *
 * @ifname:      Network interface name
 * @queue_id:    NIC RX queue index
 * @frame_size:  UMEM frame size (typically 4096)
 * @num_frames:  Number of UMEM frames (power of 2, e.g., 4096)
 *
 * Returns socket handle or NULL on failure (check errno).
 */
struct xgl_xsk *xgl_xsk_create(const char *ifname, int queue_id,
                                __u32 frame_size, __u32 num_frames);

/*
 * xgl_xsk_destroy() - Destroy socket and free UMEM.
 */
void xgl_xsk_destroy(struct xgl_xsk *xsk);

/*
 * xgl_xsk_is_zerocopy() - Check if zero-copy mode was obtained.
 */
bool xgl_xsk_is_zerocopy(const struct xgl_xsk *xsk);

/*
 * xgl_xsk_recv() - Zero-copy receive: returns pointer directly into UMEM.
 *
 * Caller MUST call xgl_xsk_recv_release() after processing.
 * Returns number of packets received (0 = none available).
 */
int xgl_xsk_recv(struct xgl_xsk *xsk, void **pkt_data, __u32 *pkt_len);

/*
 * xgl_xsk_recv_release() - Release received packet back to UMEM fill ring.
 */
void xgl_xsk_recv_release(struct xgl_xsk *xsk);

/*
 * xgl_xsk_send_alloc() - Zero-copy send: allocate a frame in UMEM TX ring.
 *
 * Caller writes packet data into the returned pointer, then calls
 * xgl_xsk_send_complete() to submit.
 * Returns pointer into UMEM or NULL if TX ring is full.
 */
void *xgl_xsk_send_alloc(struct xgl_xsk *xsk, __u32 len);

/*
 * xgl_xsk_send_complete() - Submit pending TX frames to the kernel.
 */
int xgl_xsk_send_complete(struct xgl_xsk *xsk);

/*
 * xgl_xsk_poll() - Poll for RX/TX events with timeout.
 */
int xgl_xsk_poll(struct xgl_xsk *xsk, int timeout_ms);

/*
 * xgl_xsk_get_fd() - Get XSK file descriptor (for inserting into XSKMAP).
 */
int xgl_xsk_get_fd(const struct xgl_xsk *xsk);

/*
 * xgl_xsk_recv_batch() - Batch receive: receive up to max packets in one call.
 *
 * More efficient than single xgl_xsk_recv() in a loop.
 * Returns number of packets received.
 */
int xgl_xsk_recv_batch(struct xgl_xsk *xsk,
                        void **pkt_data, __u32 *pkt_lens,
                        int max);

/*
 * xgl_xsk_recv_release_batch() - Release a batch of received packets.
 */
void xgl_xsk_recv_release_batch(struct xgl_xsk *xsk, int count);

#endif /* XGL_XSK_H */
