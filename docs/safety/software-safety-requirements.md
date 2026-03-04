# Software Safety Requirements Specification

**Project:** xdp-graph-lib
**Document ID:** XGL-SSRS-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 6, Clause 6
**Target ASIL:** ASIL-A (Phase 1), ASIL-B (Phase 2)
**Status:** Initial Release

---

## 1. Purpose and Scope

This document specifies the software safety requirements for xdp-graph-lib,
a reusable C library for building modular XDP packet-processing pipelines
using BPF tail calls.

xdp-graph-lib provides the foundational graph management layer for
safety-critical network data planes. It is designed to be integrated
into higher-level systems (e.g., GroutX) that require functional safety
certification under ISO 26262 or IEC 61508.

### 1.1 System Context

xdp-graph-lib operates at two levels:

- **BPF side (kernel):** Macros and data structures used by BPF programs
  executing in the XDP hook. These execute in a constrained environment
  enforced by the kernel BPF verifier (bounded execution, no dynamic
  allocation, stack limits).

- **Userspace side:** A static library (`libxgl.a`) that manages graph
  topology, loads BPF programs, populates PROG_ARRAY maps, reads
  statistics, and performs atomic reconfiguration.

### 1.2 Safety Boundary

The safety boundary of xdp-graph-lib encompasses:

- Metadata struct layout and access (shared between BPF and userspace)
- Graph topology management (DAG enforcement)
- BPF program loading and map sharing
- Atomic reconfiguration of the processing pipeline
- Per-node statistics collection

The following are **outside** the safety boundary:

- Individual BPF node implementations (application-specific)
- Kernel BPF verifier correctness (assumed correct per platform qualification)
- Network interface driver behavior
- Hardware behavior

### 1.3 Applicable Standards

| Standard | Relevance |
|---|---|
| ISO 26262:2018 Parts 6, 8, 9 | Software development, verification, safety analysis |
| IEC 61508:2010 Part 3 | Software safety lifecycle (alternative framework) |
| MISRA C:2012 | Coding standard (informative, adapted for BPF constraints) |

### 1.4 Definitions

| Term | Definition |
|---|---|
| Node | An independent BPF program that processes packets at one stage of the pipeline |
| Edge | A directed connection from one node to another, implemented via `bpf_tail_call()` |
| PROG_ARRAY | A BPF map (`BPF_MAP_TYPE_PROG_ARRAY`) that stores program file descriptors indexed by node ID |
| DAG | Directed Acyclic Graph — the required topology for any valid processing pipeline |
| Headroom | Memory region before the packet data (`data_meta` to `data`) used for metadata |
| Tail call | Transfer of execution to another BPF program without returning to the caller |

---

## 2. Safety Goals

The following safety goals are derived from the system-level hazard analysis.

| ID | Safety Goal | ASIL |
|---|---|---|
| SG-1 | The packet processing pipeline shall not enter an infinite loop | ASIL-A |
| SG-2 | Metadata access shall not cause out-of-bounds memory access | ASIL-A |
| SG-3 | Graph reconfiguration shall not cause packet corruption or undefined behavior | ASIL-A |
| SG-4 | The library shall not silently drop packets due to internal errors | ASIL-A |

---

## 3. Software Safety Requirements

### 3.1 Metadata Integrity

#### SSR-META-001: Metadata Struct Size

The `struct xgl_meta` shall be exactly 52 bytes.

- **Rationale:** Cross-domain agreement between BPF and userspace requires
  a fixed, known layout. Any size change indicates a structural defect.
- **Verification:** `_Static_assert`, CBMC proof, unit test
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-META-002: Metadata Fits in Headroom

The `struct xgl_meta` size shall not exceed `XGL_MAX_HEADROOM` (252 bytes).

- **Rationale:** The XDP headroom is limited by `bpf_xdp_adjust_meta()`.
  Exceeding it causes metadata allocation failure and packet loss.
- **Verification:** `_Static_assert`, CBMC proof
- **ASIL:** A
- **Derives from:** SG-2, SG-4

#### SSR-META-003: Metadata Field Offsets

Each field of `struct xgl_meta` shall be at the byte offset specified in
the interface control document (SPEC.md, Field Layout table):

| Field | Required Offset |
|---|---|
| version | 0 |
| flags | 1 |
| l2_proto | 2 |
| l3_offset | 4 |
| next_node | 6 |
| ingress_ifindex | 8 |
| timestamp_ns | 12 |
| scratch | 20 |

- **Rationale:** BPF programs and userspace tools rely on these offsets
  for interoperability. A packing or alignment change silently corrupts data.
- **Verification:** `offsetof()` assertions, CBMC proof, unit test
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-META-004: Metadata Alignment

The `struct xgl_meta` shall have 4-byte alignment.

- **Rationale:** BPF verifier requires aligned access. Misaligned access
  causes verifier rejection or undefined behavior on some architectures.
- **Verification:** `__alignof__` assertion, unit test
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-META-005: Metadata Version Validation

`XGL_META_GET()` shall return NULL if the metadata `version` field does
not equal `XGL_META_VERSION`.

- **Rationale:** Prevents nodes from interpreting stale or corrupt metadata
  from a different library version.
- **Verification:** Code review, BPF verifier (bounds check), unit test
- **ASIL:** A
- **Derives from:** SG-2, SG-4

#### SSR-META-006: Metadata Bounds Validation

`XGL_META_GET()` shall return NULL if `data_meta + sizeof(struct xgl_meta)`
exceeds `data`.

- **Rationale:** Prevents out-of-bounds read if headroom was not allocated
  or was allocated with insufficient size.
- **Verification:** Code review, BPF verifier (mandatory bounds check)
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-META-007: Metadata Zero-Initialization

`XGL_META_ALLOC()` shall zero-initialize all metadata fields before
setting the version field.

- **Rationale:** Prevents information leakage from kernel memory and
  ensures deterministic initial state for all nodes.
- **Verification:** Code review (`__builtin_memset`), unit test
- **ASIL:** A
- **Derives from:** SG-2, SG-3

### 3.2 Graph Topology

#### SSR-DAG-001: Cycle Detection

`xgl_graph_validate_dag()` shall return -1 (with `errno = ELOOP`) for
any graph that contains a directed cycle.

- **Rationale:** A cycle in the graph causes infinite tail call chains.
  The kernel limits tail calls to 33, but a cycle wastes the budget and
  causes silent packet drops at the depth limit.
- **Verification:** Unit tests (all cycle patterns), CBMC proof
  (Kahn's vs DFS equivalence for 8-node graphs), TLA+ model checking
- **ASIL:** A
- **Derives from:** SG-1

#### SSR-DAG-002: Acyclic Graph Acceptance

`xgl_graph_validate_dag()` shall return 0 for any graph that does not
contain a directed cycle.

- **Rationale:** False positives in cycle detection would reject valid
  pipeline topologies, preventing correct system operation.
- **Verification:** Unit tests (linear, diamond, complex DAGs), CBMC
  proof, TLA+ model checking
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-DAG-003: Self-Loop Detection

`xgl_graph_validate_dag()` shall detect self-loops (edges from a node
to itself) as cycles.

- **Rationale:** A self-loop is the simplest cycle and would cause a node
  to tail-call itself repeatedly.
- **Verification:** Unit test (`test_self_loop`)
- **ASIL:** A
- **Derives from:** SG-1

#### SSR-DAG-004: DAG Invariant Under Reconfiguration

After `xgl_reconfig_commit()`, the resulting graph shall be a valid DAG
if it was a valid DAG before the reconfiguration began.

- **Rationale:** Reconfiguration must not introduce cycles that would
  cause infinite loops.
- **Verification:** TLA+ temporal property (`[]IsDAG`)
- **ASIL:** A
- **Derives from:** SG-1, SG-3

#### SSR-DAG-005: No Orphan Edges

Every edge endpoint (source and destination) shall reference a valid,
active node.

- **Rationale:** An edge pointing to a non-existent node causes a tail
  call to an empty PROG_ARRAY slot, which silently fails and drops
  the packet.
- **Verification:** TLA+ invariant (`NoOrphanEdges`)
- **ASIL:** A
- **Derives from:** SG-4

### 3.3 Node Management

#### SSR-NODE-001: Valid Index Range

`xgl_graph_add_node()` shall reject node indices outside the range
`[0, XGL_MAX_NODES)` by returning `-EINVAL`.

- **Rationale:** Out-of-range indices would cause out-of-bounds access
  to internal arrays.
- **Verification:** Unit test (`test_add_invalid_index`)
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-NODE-002: Duplicate Index Prevention

`xgl_graph_add_node()` shall return `-EEXIST` if a program is already
loaded at the specified index.

- **Rationale:** Silently overwriting a loaded program could leave
  dangling references and corrupt the pipeline.
- **Verification:** Unit test (implicit in `test_add_invalid_index`)
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-NODE-003: Non-Existent Node Removal

`xgl_graph_remove_node()` shall return `-ENOENT` if no program is
loaded at the specified index.

- **Rationale:** Removing a non-existent node should be an explicit error,
  not a silent no-op, to catch logic errors in the control plane.
- **Verification:** Unit test (`test_remove_nonexistent`)
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-NODE-004: Edge Cleanup on Removal

`xgl_graph_remove_node()` shall remove all edges (both incoming and
outgoing) associated with the removed node.

- **Rationale:** Orphan edges violate SSR-DAG-005 and cause tail call
  failures.
- **Verification:** Code review, TLA+ (`RemoveNode` action)
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-NODE-005: Tail Call Fallback

Every BPF node shall have a defined fallback action after
`XGL_NEXT()` (tail call). The fallback shall execute if the tail call
fails silently.

- **Rationale:** `bpf_tail_call()` does not return an error — it simply
  falls through. Without a fallback, execution continues into
  unrelated code.
- **Verification:** Code review of all node implementations, BPF verifier
- **ASIL:** A
- **Derives from:** SG-4

### 3.4 Map Sharing

#### SSR-MAP-001: Shared PROG_ARRAY

All BPF programs within a single graph instance shall share the same
`BPF_MAP_TYPE_PROG_ARRAY` map.

- **Rationale:** If nodes use separate PROG_ARRAY maps, tail calls will
  fail because each node's map won't contain the other nodes' programs.
- **Verification:** Code review (`bpf_map__reuse_fd` in `xgl_graph_add_node`)
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-MAP-002: Shared Stats Map

All BPF programs within a single graph instance shall share the same
per-node statistics `BPF_MAP_TYPE_PERCPU_ARRAY` map.

- **Rationale:** Separate stats maps would give inconsistent and
  incomplete per-node counters.
- **Verification:** Code review (`bpf_map__reuse_fd` in `xgl_graph_add_node`)
- **ASIL:** A
- **Derives from:** SG-4

### 3.5 Reconfiguration

#### SSR-RECONFIG-001: Atomic Commit

`xgl_reconfig_commit()` shall apply all staged changes before waiting
for an RCU grace period.

- **Rationale:** Partial application could leave the pipeline in an
  inconsistent state where some nodes exist but their edges don't,
  or vice versa.
- **Verification:** Code review, integration test
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-RECONFIG-002: RCU Grace Period

`xgl_reconfig_commit()` shall wait for an RCU grace period (minimum
10ms) after applying changes.

- **Rationale:** In-flight packets on other CPUs may still reference
  the old PROG_ARRAY entries. The grace period ensures all such
  packets complete before old programs are unloaded.
- **Verification:** Code review (`usleep(10000)`)
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-RECONFIG-003: Abort Discards Changes

`xgl_reconfig_abort()` shall discard all staged changes without
modifying the active pipeline.

- **Rationale:** The operator must be able to cancel a reconfiguration
  without side effects.
- **Verification:** Code review
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-RECONFIG-004: Single Transaction

Only one reconfiguration transaction shall be active at a time per
graph instance. `xgl_reconfig_begin()` shall return `-EBUSY` if a
transaction is already in progress.

- **Rationale:** Concurrent reconfigurations could conflict and produce
  an undefined graph state.
- **Verification:** Code review
- **ASIL:** A
- **Derives from:** SG-3

### 3.6 Resource Management

#### SSR-RES-001: NULL-Safe Destroy

`xgl_graph_destroy(NULL)` shall be a safe no-op.

- **Rationale:** Defensive programming against double-free and
  error-path cleanup.
- **Verification:** Unit test (`test_destroy_null`)
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-RES-002: Complete Cleanup

`xgl_graph_destroy()` shall close all BPF objects, maps, and detach
from the network interface.

- **Rationale:** Resource leaks (file descriptors, kernel objects) can
  exhaust system resources and cause subsequent graph creation to fail.
- **Verification:** Code review, ASAN testing
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-RES-003: No Dynamic Allocation in BPF

BPF-side code (macros, data structures) shall not use dynamic memory
allocation (`malloc`, `calloc`, `free`).

- **Rationale:** The BPF verifier prohibits dynamic allocation. Any
  attempt would be rejected at load time, but the prohibition must
  be enforced at the design level.
- **Verification:** Code review, BPF verifier
- **ASIL:** A
- **Derives from:** SG-2

### 3.7 Statistics

#### SSR-STATS-001: Per-CPU Aggregation

`xgl_stats_read()` shall aggregate statistics across all CPUs for the
specified node.

- **Rationale:** Per-CPU maps store independent counters per CPU.
  Presenting raw per-CPU data as totals would be incorrect.
- **Verification:** Code review
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-STATS-002: Stats Reset

`xgl_stats_reset()` shall zero all per-CPU counters for the specified
node.

- **Rationale:** Operators need to reset counters for interval-based
  monitoring.
- **Verification:** Code review
- **ASIL:** A
- **Derives from:** SG-4

### 3.8 Error Reporting

#### SSR-ERR-001: Negative Errno Convention

All userspace functions that can fail shall return negative `errno`
values on error (or NULL for constructors).

- **Rationale:** Consistent error reporting enables reliable error
  handling in the control plane.
- **Verification:** Code review, unit tests
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-ERR-002: Input Validation

All public API functions shall validate their inputs and return
`-EINVAL` for NULL pointers or out-of-range parameters.

- **Rationale:** Defensive input validation prevents undefined behavior
  from propagating.
- **Verification:** Unit tests (`test_add_null_params`, `test_add_invalid_index`)
- **ASIL:** A
- **Derives from:** SG-2

### 3.9 Wrapper Delegation

#### SSR-WRAP-001: Delegation Transparency

All `xgl_graph_*` wrapper functions that delegate to `egl_graph_*`
shall pass arguments unchanged and return the `egl_graph_*` return
value unchanged.

- **Rationale:** The wrapper layer must not alter semantics of the
  underlying generic graph operations.
- **Verification:** Unit tests (`test_wrapper.c:test_dag_delegation_linear`,
  `test_dag_delegation_cycle`)
- **ASIL:** A
- **Derives from:** SG-3, SG-4

#### SSR-WRAP-002: Valid EGL Handle

`xgl_graph_get_egl()` shall return a non-NULL `egl_graph` pointer
for any valid `xgl_graph` instance.

- **Rationale:** Higher-level code that accesses the underlying
  `egl_graph` must always receive a valid handle.
- **Verification:** Unit test (`test_wrapper.c:test_get_egl_valid`)
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-WRAP-003: DAG Validation Before Attach

`xgl_graph_attach()` shall validate the DAG topology and return
an error (negative errno) if the graph contains a cycle, before
performing any XDP attachment.

- **Rationale:** Prevents attaching a cyclic graph to a live
  interface, which would cause infinite tail call loops (FM-DAG-04).
- **Verification:** Unit test (`test_wrapper.c:test_attach_validates_dag`),
  integration test (`test_fmea_mitigations.c:test_fm_dag_04_attach_with_cycle`)
- **ASIL:** A
- **Derives from:** SG-1

#### SSR-WRAP-004: Destroy Aborts Active Reconfig

`xgl_graph_destroy()` shall abort any active reconfiguration
transaction before freeing the graph.

- **Rationale:** Prevents stale reconfig state table entries after
  graph destruction (FM-RECONFIG-04).
- **Verification:** Unit test (`test_wrapper.c:test_destroy_aborts_reconfig`),
  integration test (`test_fmea_mitigations.c:test_fm_reconfig_04_destroy_aborts`)
- **ASIL:** A
- **Derives from:** SG-3

### 3.10 AF_XDP Sockets

#### SSR-XSK-001: Zero-Copy Preference

`xgl_xsk_create()` shall attempt `XDP_ZEROCOPY` bind first and
fall back to `XDP_COPY` only if the driver does not support it.

- **Rationale:** Zero-copy provides lower latency and higher
  throughput for safety-critical packet processing.
- **Verification:** Integration test
  (`test_xsk_privileged.c:test_xsk_zerocopy_fallback`)
- **ASIL:** A
- **Derives from:** SG-4

#### SSR-XSK-002: Destroy Releases All Resources

`xgl_xsk_destroy()` shall release the socket, UMEM, and mmap
allocation. After destroy, the socket fd shall no longer be valid.

- **Rationale:** Resource leaks can exhaust system resources and
  prevent subsequent socket creation.
- **Verification:** Integration test
  (`test_xsk_privileged.c:test_xsk_destroy_cleanup`)
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-XSK-003: XSK Input Validation

All public `xgl_xsk_*` functions shall validate their inputs and
return 0, NULL, or -EINVAL for NULL pointers or invalid parameters.

- **Rationale:** Defensive input validation prevents undefined
  behavior in the AF_XDP subsystem.
- **Verification:** Unit tests (`test_xsk.c`: 16 input validation cases)
- **ASIL:** A
- **Derives from:** SG-2

#### SSR-XSK-004: Partial Creation Cleanup

If `xgl_xsk_create()` fails at any intermediate step (UMEM, rings,
socket), all previously allocated resources shall be freed.

- **Rationale:** Partial creation must not leak mmap regions,
  file descriptors, or kernel objects.
- **Verification:** Fault injection tests
  (`test_fault_xgl.c:test_xsk_create_fault`)
- **ASIL:** A
- **Derives from:** SG-3

#### SSR-XSK-005: Graph-Level XSK Registration

`xgl_graph_create_xsk()` shall insert the XSK file descriptor
into the XSKMAP at the specified queue ID.

- **Rationale:** The XSKMAP entry is required for BPF programs
  to redirect packets to the AF_XDP socket.
- **Verification:** Integration tests
  (`test_xsk_privileged.c:test_xsk_fd_for_xskmap`,
  `test_graph_create_xsk`)
- **ASIL:** A
- **Derives from:** SG-4

---

## 4. Verification Methods Summary

| Method | Requirements Covered | Tool |
|---|---|---|
| `_Static_assert` | SSR-META-001, -002, -003, -004 | Compiler |
| CBMC bounded model checking | SSR-META-001..007, SSR-DAG-001..003 | CBMC |
| TLA+ model checking | SSR-DAG-001..005 | TLC |
| Unit tests (test_meta) | SSR-META-001..007 | GCC + Meson |
| Unit tests (test_dag) | SSR-DAG-001..003 | GCC + Meson |
| Unit tests (test_graph) | SSR-NODE-001..003, SSR-RES-001, SSR-ERR-002 | GCC + Meson |
| Unit tests (test_wrapper) | SSR-WRAP-001..004, SSR-ERR-002 | GCC + Meson |
| Unit tests (test_xsk) | SSR-XSK-003 | GCC + Meson |
| Integration test (test_pipeline) | SSR-RECONFIG-001, SSR-DAG-004 | GCC + Meson |
| Integration test (test_xsk_privileged) | SSR-XSK-001, -002, -005 | GCC + Meson |
| Integration test (test_fmea_mitigations) | SSR-WRAP-003, -004, SSR-XSK-001 | GCC + Meson |
| Fault injection (test_fault_xgl) | SSR-XSK-004, SSR-RES-002 | GCC + Meson + LD_PRELOAD |
| ASAN/UBSAN | SSR-RES-002, SSR-META-002 | GCC + Meson |
| Code review | SSR-MAP-001..002, SSR-RECONFIG-001..004, SSR-RES-003 | Manual |

---

## 5. Assumptions

| ID | Assumption |
|---|---|
| ASM-001 | The Linux kernel BPF verifier correctly enforces memory safety, bounded execution, and stack limits |
| ASM-002 | `bpf_xdp_adjust_meta()` correctly adjusts the headroom by the requested amount |
| ASM-003 | `BPF_MAP_TYPE_PROG_ARRAY` updates are atomic at the individual entry level |
| ASM-004 | `BPF_MAP_TYPE_PERCPU_ARRAY` provides correct per-CPU isolation |
| ASM-005 | libbpf correctly loads BPF ELF objects and populates maps |
| ASM-006 | The underlying hardware provides reliable packet delivery to the XDP hook |

---

## 6. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
| 1.1 | 2026-03-04 | xdp-graph-lib team | Added SSR-WRAP-001..004 (wrapper delegation), SSR-XSK-001..005 (AF_XDP sockets). Updated verification methods. |
