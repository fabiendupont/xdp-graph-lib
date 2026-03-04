/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_DEVMAP_H
#define XGL_DEVMAP_H

/*
 * XGL_DECLARE_DEVMAP(name, max) - Declare a DEVMAP for XDP_REDIRECT.
 *
 * DEVMAP_HASH allows using ifindex as key for efficient lookups.
 */
#define XGL_DECLARE_DEVMAP(name, max)                    \
    struct {                                            \
        __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);         \
        __uint(max_entries, max);                       \
        __type(key, __u32);                             \
        __type(value, struct bpf_devmap_val);           \
    } name SEC(".maps")

/*
 * XGL_DECLARE_XSKMAP(name, max) - Declare an XSKMAP for AF_XDP redirection.
 *
 * XSKMAP entries hold AF_XDP socket file descriptors, keyed by queue ID.
 */
#define XGL_DECLARE_XSKMAP(name, max)                    \
    struct {                                            \
        __uint(type, BPF_MAP_TYPE_XSKMAP);              \
        __uint(max_entries, max);                       \
        __type(key, __u32);                             \
        __type(value, __u32);                           \
    } name SEC(".maps")

/*
 * XGL_REDIRECT_MAP(devmap, ifindex, flags) - Redirect to a DEVMAP entry.
 */
#define XGL_REDIRECT_MAP(devmap, ifindex, flags) \
    bpf_redirect_map(&(devmap), (ifindex), (flags))

/*
 * XGL_REDIRECT_XSK(xskmap, queue_id, flags) - Redirect to an AF_XDP socket.
 */
#define XGL_REDIRECT_XSK(xskmap, queue_id, flags) \
    bpf_redirect_map(&(xskmap), (queue_id), (flags))

#endif /* XGL_DEVMAP_H */
