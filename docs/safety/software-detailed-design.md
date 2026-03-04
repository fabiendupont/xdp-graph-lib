# Software Detailed Design

**Project:** xdp-graph-lib
**Document ID:** XGL-SDD-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 6, Clause 8
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Purpose

This document provides per-function detailed design for the
safety-critical components of xdp-graph-lib. For ASIL-A, detailed
design is recommended but not required. This document covers the
functions directly implementing safety requirements.

---

## 2. Safety-Critical Functions

### 2.1 `xgl_graph_validate_dag()`

**File:** `src/userspace/xgl_graph.c`
**Requirement:** SSR-DAG-001, SSR-DAG-002, SSR-DAG-003

#### Algorithm: Kahn's Topological Sort (BFS)

```
Input: edges[MAX_NODES] — bitmask of outgoing edges per node
       node_fds[MAX_NODES] — loaded BPF program fds (-1 = empty)

1. Copy edges to edges_copy (preserve original)
2. For each node i (0..MAX_NODES-1):
   a. Determine if node is active:
      - is_src = edges_copy[i] != 0
      - is_dst = any edges_copy[k] has bit i set
      - is_loaded = node_fds[i] >= 0
      - active = is_src || is_dst || is_loaded
   b. If active: increment node_count
   c. For each bit j set in edges_copy[i]: in_degree[j]++

3. For each active node i with in_degree[i] == 0:
   Enqueue i

4. BFS loop:
   While queue not empty:
   a. Dequeue node
   b. processed++
   c. For each outgoing edge (node → j):
      - in_degree[j]--
      - If in_degree[j] == 0: enqueue j
   d. Clear edges_copy[node]

5. If processed < node_count:
   Return -1, errno = ELOOP  (cycle detected)
   Else:
   Return 0  (valid DAG)
```

#### Complexity

- Time: O(V + E) where V = active nodes, E = edges
- Space: O(V) for queue and in-degree arrays
- V is bounded by XGL_MAX_NODES (32)
- E is bounded by V² (1024)

#### Formal Verification

- CBMC proves equivalence with DFS for all 6-node graphs
- TLA+ proves invariant holds under all Add/Remove operations

---

### 2.2 `XGL_META_GET(ctx)` (macro)

**File:** `include/xgl/xgl_node.h`
**Requirement:** SSR-META-005, SSR-META-006

#### Logic

```
1. data = (void *)(long) ctx->data
2. data_meta = (void *)(long) ctx->data_meta
3. meta = (struct xgl_meta *) data_meta

4. If data_meta + sizeof(struct xgl_meta) <= data    [bounds check]
   AND meta->version == XGL_META_VERSION              [version check]
   Then: return meta
   Else: return NULL
```

#### BPF Verifier Interaction

The bounds check `data_meta + sizeof <= data` is **required** by the
BPF verifier. Without it, the verifier rejects the program at load
time with "invalid access to packet metadata". The version check is
an additional library-level safety mechanism.

---

### 2.3 `XGL_META_ALLOC(ctx)` (macro)

**File:** `include/xgl/xgl_node.h`
**Requirement:** SSR-META-007

#### Logic

```
1. Call bpf_xdp_adjust_meta(ctx, -sizeof(struct xgl_meta))
2. If failed: return NULL

3. Re-read data and data_meta pointers (adjusted by kernel)
4. meta = (struct xgl_meta *) data_meta

5. If data_meta + sizeof(struct xgl_meta) <= data:   [bounds check]
   a. memset(meta, 0, sizeof)                         [zero-init]
   b. meta->version = XGL_META_VERSION                [set version]
   c. return meta
   Else: return NULL
```

#### Post-conditions

- All 52 bytes are zero except `version` (= 1)
- Pointer is within [data_meta, data) bounds
- BPF verifier has validated the access pattern

---

### 2.4 `xgl_graph_add_node()`

**File:** `src/userspace/xgl_graph.c`
**Requirement:** SSR-NODE-001, SSR-NODE-002, SSR-MAP-001, SSR-MAP-002

#### Logic

```
1. Validate inputs: g != NULL, 0 <= index < MAX_NODES,
   obj_path != NULL, prog_name != NULL
   → -EINVAL on failure

2. Check node_fds[index] >= 0 → -EEXIST if occupied

3. ensure_maps(g): lazily create PROG_ARRAY and stats maps
   → propagate error

4. bpf_object__open(obj_path)
   → -errno on failure

5. For each map in the BPF object:
   a. If name == "xgl_prog_array": reuse_fd(graph's PROG_ARRAY)
   b. If name == "xgl_node_stats": reuse_fd(graph's stats map)
   → propagate error, close object on failure

6. bpf_object__load(obj)
   → propagate error, close object on failure

7. Find program by name: bpf_object__find_program_by_name
   → -ENOENT if not found

8. Get program fd: bpf_program__fd
   → -ENOENT if invalid

9. Insert into PROG_ARRAY: bpf_map_update_elem(key=index, val=fd)
   → propagate error

10. Store: node_objs[index] = obj, node_fds[index] = fd
11. Return 0
```

---

### 2.5 `xgl_graph_remove_node()`

**File:** `src/userspace/xgl_graph.c`
**Requirement:** SSR-NODE-003, SSR-NODE-004

#### Logic

```
1. Validate: g != NULL, 0 <= index < MAX_NODES → -EINVAL
2. Check node_fds[index] < 0 → -ENOENT

3. Remove from PROG_ARRAY (if map exists):
   bpf_map_delete_elem(key=index)

4. Close BPF object (if exists):
   bpf_object__close(node_objs[index])

5. Clear: node_fds[index] = -1

6. Clear all edges involving this node:
   a. edges[index] = 0               (outgoing)
   b. For each i: edges[i] &= ~(1<<index)  (incoming)

7. Wait RCU grace period: usleep(10ms)

8. Return 0
```

---

### 2.6 `xgl_graph_attach()`

**File:** `src/userspace/xgl_graph.c`
**Requirement:** SSR-DAG-004

#### Logic

```
1. Validate: g != NULL, ifname != NULL → -EINVAL

2. Validate DAG: xgl_graph_validate_dag(g)
   → propagate error (-1 with ELOOP if cycle)

3. Find root program: first node_fds[i] >= 0
   → -ENOENT if no nodes loaded

4. Resolve interface: if_nametoindex(ifname)
   → -errno on failure

5. Attach XDP: bpf_xdp_attach(ifindex, root_fd, 0, NULL)
   → propagate error

6. Store: attached_ifindex = ifindex
7. Return 0
```

---

### 2.7 `xgl_graph_destroy()`

**File:** `src/userspace/xgl_graph.c`
**Requirement:** SSR-RES-001, SSR-RES-002

#### Logic

```
1. If g == NULL: return (no-op)

2. Abort any active reconfiguration: xgl_reconfig_abort(g)

3. If attached: bpf_xdp_detach(ifindex)

4. For each node i:
   a. If node_objs[i]: bpf_object__close
   b. node_fds[i] = -1

5. If prog_array_fd >= 0: close(fd)
6. If stats_map_fd >= 0: close(fd)

7. free(g)
```

---

## 3. Data Structure Details

### 3.1 `struct xgl_graph` (opaque)

```c
struct xgl_graph {
    char name[64];                           /* Human-readable name */
    int prog_array_fd;                       /* PROG_ARRAY map fd (-1 if lazy) */
    int stats_map_fd;                        /* Stats PERCPU_ARRAY fd (-1 if lazy) */
    struct bpf_object *node_objs[32];        /* Loaded BPF objects (NULL = empty) */
    int node_fds[32];                        /* Program fds (-1 = empty) */
    int attached_ifindex;                    /* XDP-attached interface (0 = none) */
    __u32 edges[32];                         /* Bitmask of outgoing edges per node */
};
```

### 3.2 `struct xgl_meta` (packed, shared)

See `include/xgl/xgl_meta.h` — 52 bytes, field layout documented
in XGL-SSRS-001 Section 3.1.

---

## 4. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
