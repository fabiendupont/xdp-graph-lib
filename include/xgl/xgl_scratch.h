/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef XGL_SCRATCH_H
#define XGL_SCRATCH_H

/*
 * XGL_DECLARE_SCRATCH(name, value_type) - Declare a per-CPU scratch map.
 *
 * Per-CPU scratch maps provide node-private temporary storage that
 * persists across a single packet's processing within one node.
 * Each CPU gets its own copy, so no locking is needed.
 *
 * Preconditions:
 *   - value_type must be a fixed-size type
 *
 * Postconditions:
 *   - map has exactly 1 entry per CPU
 */
#define XGL_DECLARE_SCRATCH(name, value_type)            \
    struct {                                            \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);        \
        __uint(max_entries, 1);                         \
        __type(key, __u32);                             \
        __type(value, value_type);                      \
    } name SEC(".maps")

/*
 * XGL_SCRATCH_GET(map) - Look up the per-CPU scratch entry.
 *
 * Returns: pointer to the per-CPU value, or NULL if lookup fails.
 */
#define XGL_SCRATCH_GET(map)                             \
    ({                                                  \
        __u32 _k = 0;                                   \
        bpf_map_lookup_elem(&(map), &_k);               \
    })

#endif /* XGL_SCRATCH_H */
