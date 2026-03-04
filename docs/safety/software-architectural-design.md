# Software Architectural Design

**Project:** xdp-graph-lib
**Document ID:** XGL-SAD-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 6, Clause 7
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Purpose

This document describes the software architecture of xdp-graph-lib,
covering component decomposition, interfaces, data flows, safety
mechanisms, and freedom-from-interference arguments as required by
ISO 26262 Part 6, Clause 7.

---

## 2. Architectural Overview

xdp-graph-lib operates across two execution domains with a strict
interface boundary:

```
┌─────────────────────────────────────────────────────────┐
│                    USERSPACE DOMAIN                       │
│                                                           │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌───────────┐  │
│  │ xgl_graph│  │xgl_loader│  │xgl_stats│ │xgl_reconfig│ │
│  │          │  │          │  │         │  │           │  │
│  │ Topology │  │ BPF load │  │ Counter │  │ Atomic    │  │
│  │ DAG valid│  │ Map share│  │ Aggr.   │  │ Commit    │  │
│  └─────┬────┘  └────┬─────┘  └────┬────┘  └─────┬─────┘  │
│        │            │             │              │        │
│  ──────┴────────────┴─────────────┴──────────────┴─────── │
│                    libbpf / bpf() syscall                  │
└────────────────────────────┬──────────────────────────────┘
                             │
════════════════════════════╪══════════════════════════════
                             │  KERNEL BOUNDARY
┌────────────────────────────┴──────────────────────────────┐
│                    KERNEL / BPF DOMAIN                     │
│                                                           │
│  ┌────────────┐    ┌─────────┐    ┌─────────┐            │
│  │ xgl_dispatch│──►│ Node 0  │──►│ Node 1  │──► ...     │
│  │ (root)     │    │         │    │         │            │
│  └────────────┘    └─────────┘    └─────────┘            │
│       │                │               │                  │
│       ▼                ▼               ▼                  │
│  ┌─────────────────────────────────────────────┐         │
│  │  Shared BPF Maps                            │         │
│  │  ┌──────────────┐  ┌────────────────────┐  │         │
│  │  │ PROG_ARRAY   │  │ PERCPU_ARRAY stats │  │         │
│  │  │ (tail calls) │  │ (per-node counters)│  │         │
│  │  └──────────────┘  └────────────────────┘  │         │
│  └─────────────────────────────────────────────┘         │
│                                                           │
│  ┌─────────────────────────────────────────────┐         │
│  │  XDP Packet Headroom                        │         │
│  │  ┌──────────────────────────────────────┐   │         │
│  │  │ struct xgl_meta (52 bytes, packed)   │   │         │
│  │  └──────────────────────────────────────┘   │         │
│  └─────────────────────────────────────────────┘         │
└───────────────────────────────────────────────────────────┘
```

### 2.1 Execution Domains

| Domain | Characteristics | Safety Properties |
|---|---|---|
| Userspace | Runs as normal Linux process. Dynamic allocation. Full libc. | Resource management, input validation, topology enforcement |
| BPF/Kernel | Runs in kernel XDP hook. Verified by BPF verifier. No allocation. 256-byte stack. Max 33 tail calls. | Memory safety (verifier-enforced), bounded execution, per-CPU isolation |

### 2.2 Component Summary

| Component | Domain | Responsibility | Safety Role |
|---|---|---|---|
| `xgl_meta.h` | Both | Metadata struct definition | Cross-domain interface agreement |
| `xgl_node.h` | BPF | Node macros (ALLOC, GET, NEXT) | Headroom access safety, version check |
| `xgl_edge.h` | BPF | PROG_ARRAY map declaration | Tail call topology |
| `xgl_scratch.h` | BPF | Per-CPU scratch maps | Node-private temporary data |
| `xgl_stats.h` | Both | Per-node statistics | Observability, error detection |
| `xgl_graph.c` | Userspace | Graph lifecycle, DAG validation | Cycle prevention, resource management |
| `xgl_loader.c` | Userspace | BPF program loading, map sharing | Correct map sharing across nodes |
| `xgl_stats.c` | Userspace | Stats aggregation and reset | Per-CPU aggregation correctness |
| `xgl_reconfig.c` | Userspace | Atomic reconfiguration | Staged commit, RCU grace period |
| `xgl_dispatch.bpf.c` | BPF | Root dispatcher | Metadata allocation, entry point |

---

## 3. Component Interfaces

### 3.1 Cross-Domain Interface: `struct xgl_meta`

The metadata struct is the **only data structure shared between BPF and
userspace** at runtime (via XDP headroom). Its layout is frozen:

- Defined in `include/xgl/xgl_meta.h`
- 52 bytes, `__attribute__((packed, aligned(4)))`
- Verified by `_Static_assert` at compile time
- Verified by CBMC at analysis time
- Version field enables forward compatibility detection

**Freedom from interference:** BPF programs access metadata via
validated pointers (bounds + version check). The BPF verifier ensures
no out-of-bounds access. Userspace never accesses packet headroom
directly — it only manages the graph topology.

### 3.2 Shared Maps

Two BPF maps are shared across all nodes in a graph:

| Map | Type | Key | Value | Sharing Mechanism |
|---|---|---|---|---|
| `xgl_prog_array` | `PROG_ARRAY` | `__u32` node index | `__u32` prog fd | `bpf_map__reuse_fd()` at load time |
| `xgl_node_stats` | `PERCPU_ARRAY` | `__u32` node index | `struct xgl_node_stats` | `bpf_map__reuse_fd()` at load time |

**Freedom from interference:** PROG_ARRAY updates are atomic per-entry
(kernel guarantee). PERCPU_ARRAY provides per-CPU isolation — no
locking needed.

### 3.3 Userspace API Boundary

All public functions follow the convention:
- Return `0` on success, negative `errno` on failure
- Constructors return pointer (NULL on failure)
- All inputs validated at entry (`-EINVAL` for invalid)
- No global mutable state except reconfig side-table

---

## 4. Data Flow

### 4.1 Packet Processing (BPF Domain)

```
NIC → XDP Hook
  │
  ▼
xgl_dispatch (root)
  ├─ XGL_META_ALLOC(ctx)     ← allocate headroom
  ├─ set ingress_ifindex      ← record origin
  ├─ set timestamp_ns         ← record arrival time
  ├─ XGL_STATS_INC_RX(...)   ← count packet
  ├─ XGL_NEXT(ctx, map, 0)   ← tail call to node 0
  └─ XDP_DROP                ← fallback if tail call fails
        │
        ▼
Node 0 (e.g., classifier)
  ├─ XGL_META_GET(ctx)        ← read metadata (version + bounds check)
  ├─ process packet            ← node-specific logic
  ├─ set meta->next_node       ← determine next hop
  ├─ XGL_NEXT(ctx, map, next)  ← tail call to next node
  └─ XDP_PASS                  ← fallback
        │
        ▼
Node N (e.g., forwarder)
  ├─ XGL_META_GET(ctx)
  ├─ process packet
  ├─ XGL_STATS_INC_TX(...)
  └─ XDP_PASS / XDP_REDIRECT  ← terminal action
```

**Key invariants maintained throughout:**
1. Metadata is always initialized before first access (ALLOC in root)
2. Every node checks META_GET return for NULL
3. Every tail call has a fallback action
4. Tail call depth bounded by kernel (max 33)

### 4.2 Graph Management (Userspace Domain)

```
Application
  │
  ├─ xgl_graph_create("name")
  │     └─ allocate graph struct (maps created lazily)
  │
  ├─ xgl_graph_add_node(g, 0, "dispatch.o", "xgl_dispatch")
  │     ├─ ensure_maps()              ← create PROG_ARRAY + stats if first node
  │     ├─ bpf_object__open()         ← load BPF ELF
  │     ├─ bpf_map__reuse_fd()        ← share PROG_ARRAY + stats maps
  │     ├─ bpf_object__load()         ← load into kernel (verifier runs here)
  │     └─ bpf_map_update_elem()      ← insert prog fd into PROG_ARRAY[0]
  │
  ├─ xgl_graph_add_edge(g, 0, 1)     ← record topology for DAG validation
  │
  ├─ xgl_graph_validate_dag(g)        ← Kahn's algorithm, return -1 if cycle
  │
  ├─ xgl_graph_attach(g, "eth0")
  │     ├─ xgl_graph_validate_dag()   ← mandatory DAG check before attach
  │     └─ bpf_xdp_attach()           ← attach root program to NIC
  │
  └─ xgl_graph_destroy(g)
        ├─ xgl_reconfig_abort()       ← clean up reconfig state
        ├─ bpf_xdp_detach()           ← detach from NIC
        ├─ bpf_object__close() × N    ← unload all BPF programs
        └─ close(maps), free(g)       ← release resources
```

### 4.3 Atomic Reconfiguration

```
xgl_reconfig_begin(g)
  └─ snapshot state, mark active
        │
xgl_reconfig_add_node(g, 2, ...)
xgl_reconfig_remove_node(g, 1)
  └─ stage changes (no BPF operations)
        │
   ┌────┴────┐
   │         │
 commit    abort
   │         │
   ├─ apply  └─ discard staged
   │  staged     changes, clear
   │  changes    active flag
   │
   ├─ usleep(10ms)  ← RCU grace period
   └─ clear active flag
```

---

## 5. Safety Mechanisms

### 5.1 Compile-Time

| Mechanism | What It Prevents | Components |
|---|---|---|
| `_Static_assert` | Struct layout drift | `xgl_meta.h` |
| `-Wall -Wextra -Werror` | Undefined behavior, implicit conversions | All `.c` files |
| `-Wconversion -Wshadow` | Silent type coercion, variable shadowing | All `.c` files |
| BPF verifier | Memory safety, bounded execution, stack overflow | All `.bpf.c` files |

### 5.2 Run-Time

| Mechanism | What It Prevents | Components |
|---|---|---|
| Input validation | NULL deref, out-of-range access | All public functions |
| Version check in META_GET | Stale/corrupt metadata access | `xgl_node.h` |
| Bounds check in META_GET | Headroom buffer overread | `xgl_node.h` |
| DAG validation (Kahn's) | Cyclic pipelines (infinite loops) | `xgl_graph.c` |
| Mandatory DAG check in attach | Attaching cyclic graph to NIC | `xgl_graph.c` |
| RCU grace period | Use-after-free of removed BPF program | `xgl_graph.c`, `xgl_reconfig.c` |
| Reconfig abort on destroy | Stale reconfig state after graph freed | `xgl_graph.c` |
| Tail call fallback | Silent execution past failed tail call | All BPF nodes |

### 5.3 Formal Verification

| Tool | What It Proves | Scope |
|---|---|---|
| CBMC (meta bounds) | All field accesses within headroom | `struct xgl_meta` |
| CBMC (DAG cycle) | Kahn's ≡ DFS for all 6-node graphs | `xgl_graph_validate_dag` |
| TLA+ (GraphTopology) | DAG invariant preserved under all operations | Graph add/remove/edge |

---

## 6. Freedom from Interference

### 6.1 BPF Domain Isolation

The BPF verifier guarantees:
- **Memory isolation:** Each BPF program can only access its own stack,
  maps it was loaded with, and packet data within bounds.
- **Bounded execution:** Maximum 1M verified instructions, 33 tail call
  depth, 256-byte stack per program.
- **No shared mutable state** between programs except via BPF maps
  (which provide atomic per-entry updates).

### 6.2 Per-CPU Isolation

- Statistics maps are `PERCPU_ARRAY` — each CPU has independent counters.
  No locking, no contention, no interference between CPUs.
- Scratch maps are `PERCPU_ARRAY` — node-private data is CPU-local.

### 6.3 Userspace / BPF Boundary

- Userspace manages topology (PROG_ARRAY) and reads stats (PERCPU_ARRAY).
- BPF programs process packets and write stats.
- No direct memory sharing — all communication through BPF maps.
- Map updates are atomic per-entry (kernel guarantee).

### 6.4 Reconfiguration Safety

- Staged commit pattern prevents partial application visibility.
- RCU grace period (10ms) ensures in-flight packets complete before
  old programs are freed.
- Reconfig state is cleaned up on graph destruction.

---

## 7. Degradation Modes

| Condition | Behavior | Detection |
|---|---|---|
| Metadata allocation fails | Root node drops all packets (XDP_DROP) | Stats: drops counter increases |
| Tail call to missing node | Packet falls through to fallback action | Stats: error counter increases |
| DAG validation fails | `attach()` returns error, pipeline not activated | Immediate error return |
| BPF program fails to load | `add_node()` returns error | Immediate error return |
| Stats map not shared | Counters per-node are independent (incorrect totals) | Operational monitoring |

All degradation modes result in either:
1. **Controlled packet drop** (XDP_DROP) — safe, detectable
2. **Packet passed to kernel** (XDP_PASS) — safe, suboptimal
3. **Immediate error return** — caller can handle

No degradation mode results in packet corruption or silent misrouting.

---

## 8. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
