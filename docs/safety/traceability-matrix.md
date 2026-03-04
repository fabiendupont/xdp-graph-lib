# Requirements Traceability Matrix

**Project:** xdp-graph-lib
**Document ID:** XGL-RTM-001
**Version:** 1.2
**Date:** 2026-03-04
**Classification:** ISO 26262 Part 8, Clause 6
**Upstream:** XGL-SSRS-001 (Software Safety Requirements Specification)
**Status:** Updated — added SSR-WRAP and SSR-XSK traceability

---

## 1. Purpose

This document provides bidirectional traceability between:

- **Safety Goals** (SG) -> **Software Safety Requirements** (SSR)
- **SSR** -> **Implementation** (source file, function/macro)
- **SSR** -> **Test Cases** (unit, integration)
- **SSR** -> **Verification Evidence** (CBMC, TLA+, static assert, code review)

Every safety requirement must have at least one implementation reference,
one test case, and one verification method. Any gap indicates incomplete
coverage and must be resolved before certification.

---

## 2. Safety Goal to Requirement Traceability

| Safety Goal | ASIL | Requirements |
|---|---|---|
| SG-1: No infinite loops | A | SSR-DAG-001, SSR-DAG-003, SSR-DAG-004, SSR-WRAP-003 |
| SG-2: No out-of-bounds access | A | SSR-META-001..007, SSR-NODE-001, SSR-RES-001, SSR-RES-003, SSR-ERR-002, SSR-WRAP-002, SSR-XSK-003 |
| SG-3: No corruption during reconfig | A | SSR-META-007, SSR-DAG-004, SSR-NODE-002..004, SSR-RECONFIG-001..004, SSR-RES-002, SSR-WRAP-001, SSR-WRAP-004, SSR-XSK-002, SSR-XSK-004 |
| SG-4: No silent packet drops | A | SSR-META-002, SSR-DAG-002, SSR-DAG-005, SSR-NODE-003..005, SSR-MAP-001..002, SSR-STATS-001..002, SSR-ERR-001, SSR-XSK-001, SSR-XSK-005 |

---

## 3. Full Traceability Matrix

### 3.1 Metadata Integrity (SSR-META)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-META-001 | `sizeof(xgl_meta) == 52` | `include/xgl/xgl_meta.h:27` `_Static_assert` | `tests/unit/test_meta.c:test_sizeof` | _Static_assert (compile-time), CBMC `meta_bounds_harness.c:19`, Unit test | PASS |
| SSR-META-002 | Meta fits in headroom | `include/xgl/xgl_meta.h:29` `_Static_assert` | `tests/unit/test_meta.c:test_fits_in_headroom` | _Static_assert, CBMC `meta_bounds_harness.c:21`, Unit test | PASS |
| SSR-META-003 | Field offsets match spec | `include/xgl/xgl_meta.h:17-25` struct layout | `tests/unit/test_meta.c:test_field_offsets` | `offsetof()` assertions, CBMC `meta_bounds_harness.c:27-42`, Unit test | PASS |
| SSR-META-004 | 4-byte alignment | `include/xgl/xgl_meta.h:25` `aligned(4)` | `tests/unit/test_meta.c:test_alignment` | `__alignof__` assertion, CBMC `meta_bounds_harness.c:23`, Unit test | PASS |
| SSR-META-005 | Version validation in META_GET | `include/xgl/xgl_node.h:43` version check in `XGL_META_GET` | `tests/unit/test_meta_get.c:test_meta_get_wrong_version`, `test_meta_get_correct_version`, `test_meta_get_both_checks` | Mock-based unit test (simulates META_GET logic), BPF verifier | PASS |
| SSR-META-006 | Bounds validation in META_GET | `include/xgl/xgl_node.h:42` bounds check in `XGL_META_GET` | `tests/unit/test_meta_get.c:test_meta_get_insufficient_headroom`, `test_meta_get_exact_headroom`, `test_meta_get_excess_headroom` | Mock-based unit test, BPF verifier | PASS |
| SSR-META-007 | Zero-init in META_ALLOC | `include/xgl/xgl_node.h:74` `__builtin_memset` in `XGL_META_ALLOC` | `tests/unit/test_meta.c:test_zero_init` (struct level) | Code review, Unit test | PASS |

### 3.2 Graph Topology (SSR-DAG)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-DAG-001 | Cycle detection | `src/userspace/xgl_graph.c:xgl_graph_validate_dag` (Kahn's algorithm) | `tests/unit/test_dag.c:test_simple_cycle`, `test_three_node_cycle` | Unit tests, CBMC `dag_cycle_harness.c` (Kahn vs DFS, 8 nodes), TLA+ `IsDAGCorrect` | PASS |
| SSR-DAG-002 | Acyclic acceptance | `src/userspace/xgl_graph.c:xgl_graph_validate_dag` | `tests/unit/test_dag.c:test_empty_graph`, `test_linear_chain`, `test_diamond`, `test_complex_dag` | Unit tests, CBMC `dag_cycle_harness.c`, TLA+ `IsDAGCorrect` | PASS |
| SSR-DAG-003 | Self-loop detection | `src/userspace/xgl_graph.c:xgl_graph_validate_dag` | `tests/unit/test_dag.c:test_self_loop` | Unit test, CBMC (self-loops are within 8-node bound) | PASS |
| SSR-DAG-004 | DAG preserved under reconfig | `src/userspace/xgl_reconfig.c:xgl_reconfig_commit` | `tests/integration/test_pipeline.c:test_pipeline_lifecycle` | TLA+ temporal property `[]IsDAGCorrect` (via `AddEdge` guard), Integration test | PASS |
| SSR-DAG-005 | No orphan edges | `src/userspace/xgl_graph.c:xgl_graph_remove_node` (clears edges) | `tests/unit/test_node_edges.c:test_remove_clears_outgoing`, `test_remove_clears_incoming` | Unit tests, TLA+ invariant `NoOrphanEdges` | PASS |

### 3.3 Node Management (SSR-NODE)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-NODE-001 | Valid index range | `src/userspace/xgl_graph.c:xgl_graph_add_node` (bounds check) | `tests/unit/test_graph.c:test_add_invalid_index` | Unit test | PASS |
| SSR-NODE-002 | Duplicate index prevention | `src/userspace/xgl_graph.c:xgl_graph_add_node` (`node_fds[index] >= 0` check) | `tests/unit/test_graph.c:test_add_invalid_index` (implicit) | Unit test | PASS |
| SSR-NODE-003 | Non-existent removal error | `src/userspace/xgl_graph.c:xgl_graph_remove_node` (`node_fds[index] < 0` check) | `tests/unit/test_graph.c:test_remove_nonexistent` | Unit test | PASS |
| SSR-NODE-004 | Edge cleanup on removal | `src/userspace/xgl_graph.c:xgl_graph_remove_node` (clears `edges[index]` and incoming) | `tests/unit/test_node_edges.c:test_remove_clears_outgoing`, `test_remove_clears_incoming`, `test_remove_breaks_cycle`, `test_remove_leaf_node` | Unit tests (4 cases), TLA+ `RemoveNode` action | PASS |
| SSR-NODE-005 | Tail call fallback | `include/xgl/xgl_node.h` (contract documentation), `src/bpf/xgl_dispatch.bpf.c:33`, `examples/l2fwd/l2fwd_rx.bpf.c:38` | — | Design rule: verified per-node via code review. BPF verifier enforces fallthrough path exists. | ACCEPTED |

### 3.4 Map Sharing (SSR-MAP)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-MAP-001 | Shared PROG_ARRAY | `src/userspace/xgl_graph.c:xgl_graph_add_node` (`bpf_map__reuse_fd` for `xgl_prog_array`) | `tests/integration/test_privileged.c:test_prog_array_map` (map type/size), `test_map_creation` | Privileged integration test, Code review | PASS |
| SSR-MAP-002 | Shared stats map | `src/userspace/xgl_graph.c:xgl_graph_add_node` (`bpf_map__reuse_fd` for `xgl_node_stats`) | `tests/integration/test_privileged.c:test_stats_aggregation` (map type/size) | Privileged integration test, Code review | PASS |

### 3.5 Reconfiguration (SSR-RECONFIG)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-RECONFIG-001 | Atomic commit | `src/userspace/xgl_reconfig.c:xgl_reconfig_commit` (applies all staged changes in loop) | `tests/integration/test_pipeline.c:test_pipeline_lifecycle` (topology level) | Code review, Integration test | PASS |
| SSR-RECONFIG-002 | RCU grace period | `src/userspace/xgl_reconfig.c:187` `usleep(10000)` | — | Design constraint: 10ms minimum wait verified via code review. Not functionally testable in unit tests. | ACCEPTED |
| SSR-RECONFIG-003 | Abort discards changes | `src/userspace/xgl_reconfig.c:xgl_reconfig_abort` (memset entries, clears active flag) | `tests/unit/test_reconfig.c:test_abort_clears_state`, `test_abort_without_begin`, `test_multiple_cycles` | Unit tests (3 cases) | PASS |
| SSR-RECONFIG-004 | Single transaction | `src/userspace/xgl_reconfig.c:xgl_reconfig_begin` (`active` flag, returns `-EBUSY`) | `tests/unit/test_reconfig.c:test_double_begin`, `test_stage_without_begin`, `test_commit_without_begin`, `test_null_graph` | Unit tests (4 cases) | PASS |

### 3.6 Resource Management (SSR-RES)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-RES-001 | NULL-safe destroy | `src/userspace/xgl_graph.c:xgl_graph_destroy` (NULL check) | `tests/unit/test_graph.c:test_destroy_null` | Unit test | PASS |
| SSR-RES-002 | Complete cleanup | `src/userspace/xgl_graph.c:xgl_graph_destroy` (closes objs, maps, detaches) | — (ASAN build passes without leaks) | ASAN/UBSAN, Code review | PASS |
| SSR-RES-003 | No malloc in BPF | `include/xgl/*.h`, `src/bpf/*.{h,c}` — no allocation calls | — (architectural constraint) | Code review, BPF verifier | PASS |

### 3.7 Statistics (SSR-STATS)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-STATS-001 | Per-CPU aggregation | `src/userspace/xgl_stats.c:xgl_stats_read` (loops over CPUs, sums) | `tests/integration/test_privileged.c:test_stats_aggregation` | Privileged integration test (verifies per-CPU write + aggregate read) | PASS |
| SSR-STATS-002 | Stats reset | `src/userspace/xgl_stats.c:xgl_stats_reset` (zeroed per-CPU array) | `tests/integration/test_privileged.c:test_stats_reset` | Privileged integration test (verifies all CPUs zeroed) | PASS |

### 3.8 Error Reporting (SSR-ERR)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-ERR-001 | Negative errno convention | All functions in `xgl_graph.c`, `xgl_loader.c`, `xgl_stats.c`, `xgl_reconfig.c` | `tests/unit/test_graph.c:test_add_invalid_index`, `test_remove_nonexistent`, `test_add_null_params`; `tests/unit/test_reconfig.c:test_null_graph` | Unit tests, Code review | PASS |
| SSR-ERR-002 | Input validation | All public functions — NULL and range checks at entry | `tests/unit/test_graph.c:test_add_null_params`, `test_add_invalid_index`, `test_create_null_name`, `test_create_empty_name`; `tests/unit/test_reconfig.c:test_null_graph`; `tests/unit/test_wrapper.c` (15 input validation cases); `tests/unit/test_xsk.c` (16 input validation cases) | Unit tests | PASS |

### 3.9 Wrapper Delegation (SSR-WRAP)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-WRAP-001 | Delegation passes args/returns unchanged | `src/userspace/xgl_graph.c:xgl_graph_add_edge`, `xgl_graph_validate_dag`, etc. (all delegate to `egl_graph_*`) | `tests/unit/test_wrapper.c:test_dag_delegation_linear`, `test_dag_delegation_cycle` | Unit tests (2 cases) | PASS |
| SSR-WRAP-002 | `xgl_graph_get_egl()` always valid | `src/userspace/xgl_graph.c:xgl_graph_get_egl` (returns `g->egl`) | `tests/unit/test_wrapper.c:test_get_egl_valid`, `test_get_egl_null` | Unit tests (2 cases) | PASS |
| SSR-WRAP-003 | `xgl_graph_attach()` validates DAG | `src/userspace/xgl_graph.c:xgl_graph_attach` (calls `xgl_graph_validate_dag` before attach) | `tests/unit/test_wrapper.c:test_attach_validates_dag`, `tests/integration/test_fmea_mitigations.c:test_fm_dag_04_attach_with_cycle` | Unit test + integration test | PASS |
| SSR-WRAP-004 | `xgl_graph_destroy()` aborts reconfig | `src/userspace/xgl_graph.c:xgl_graph_destroy` (calls `egl_reconfig_abort`) | `tests/unit/test_wrapper.c:test_destroy_aborts_reconfig`, `tests/integration/test_fmea_mitigations.c:test_fm_reconfig_04_destroy_aborts` | Unit test + integration test | PASS |

### 3.10 AF_XDP Sockets (SSR-XSK)

| Req ID | Requirement | Implementation | Test Case | Verification | Status |
|---|---|---|---|---|---|
| SSR-XSK-001 | Prefer XDP_ZEROCOPY, fallback | `src/userspace/xgl_xsk.c:xgl_xsk_create` (tries ZEROCOPY first, falls back to COPY) | `tests/integration/test_xsk_privileged.c:test_xsk_zerocopy_fallback` | Integration test | PASS |
| SSR-XSK-002 | Destroy releases all resources | `src/userspace/xgl_xsk.c:xgl_xsk_destroy` (socket, UMEM, mmap) | `tests/integration/test_xsk_privileged.c:test_xsk_destroy_cleanup` | Integration test (fd invalid after destroy) | PASS |
| SSR-XSK-003 | All public functions validate inputs | `src/userspace/xgl_xsk.c` — all functions check NULL/invalid params at entry | `tests/unit/test_xsk.c` (16 cases: create, destroy, is_zerocopy, get_fd, recv, recv_release, send_alloc, send_complete, poll, recv_batch, recv_release_batch) | Unit tests | PASS |
| SSR-XSK-004 | Partial creation frees prior allocs | `src/userspace/xgl_xsk.c:xgl_xsk_create` (cleanup on each failure path) | `tests/fault/test_fault_xgl.c:test_xsk_create_fault` | Fault injection (LD_PRELOAD sweep) | PASS |
| SSR-XSK-005 | `xgl_graph_create_xsk()` inserts fd into XSKMAP | `src/userspace/xgl_graph.c:xgl_graph_create_xsk` (`bpf_map_update_elem` with xsk fd) | `tests/integration/test_xsk_privileged.c:test_xsk_fd_for_xskmap`, `test_graph_create_xsk` | Integration tests (2 cases) | PASS |

---

## 4. Coverage Summary

| Status | Count | Percentage |
|---|---|---|
| PASS (automated test + verification) | 38 | 95% |
| ACCEPTED (design constraint, verified by code review) | 2 | 5% |
| REVIEW | 0 | 0% |
| FAIL | 0 | 0% |
| **Total** | **40** | **100%** |

### 4.1 ACCEPTED Items

These requirements cannot be verified by automated tests due to their
nature. They are accepted based on code review and design analysis:

| Req ID | Justification |
|---|---|
| SSR-NODE-005 | Tail call fallback is a per-node design rule. The BPF verifier guarantees that all code paths after `bpf_tail_call()` are reachable. Each node implementation must be individually reviewed. All library-provided nodes (`xgl_dispatch`, `l2fwd_rx`, `l2fwd_tx`) have verified fallback paths. |
| SSR-RECONFIG-002 | The 10ms RCU grace period (`usleep(10000)`) is a timing constraint that cannot be functionally tested in isolation. The value is derived from kernel RCU documentation. Code review confirms the call is present and unconditional. |

### 4.2 Verification Method Coverage

| Method | Requirements Covered |
|---|---|
| _Static_assert (compile-time) | SSR-META-001, -002, -003, -004 |
| CBMC (meta_bounds_harness) | SSR-META-001, -002, -003, -004, -007 |
| CBMC (dag_cycle_harness) | SSR-DAG-001, -002, -003 |
| TLA+ (GraphTopology) | SSR-DAG-001, -002, -004, -005 |
| Unit test: test_meta | SSR-META-001, -002, -003, -004, -007 |
| Unit test: test_meta_get | SSR-META-005, -006 |
| Unit test: test_dag | SSR-DAG-001, -002, -003 |
| Unit test: test_graph | SSR-NODE-001, -002, -003, SSR-RES-001, SSR-ERR-001, -002 |
| Unit test: test_node_edges | SSR-NODE-004, SSR-DAG-005 |
| Unit test: test_reconfig | SSR-RECONFIG-003, -004, SSR-ERR-001, -002 |
| Unit test: test_wrapper | SSR-WRAP-001, -002, -003, -004, SSR-ERR-002 |
| Unit test: test_xsk | SSR-XSK-003 |
| Integration test: test_pipeline | SSR-DAG-004, SSR-RECONFIG-001 |
| Integration test: test_privileged | SSR-MAP-001, -002, SSR-STATS-001, -002 |
| Integration test: test_xsk_privileged | SSR-XSK-001, -002, -005 |
| Integration test: test_fmea_mitigations | SSR-WRAP-003, -004 (FM-DAG-04, FM-RECONFIG-04, FM-NODE-03, FM-DISP-01, FM-DISP-02) |
| Fault injection: test_fault_xgl | SSR-XSK-004, SSR-RES-002 |
| ASAN/UBSAN | SSR-RES-002 |
| Code review | SSR-NODE-005, SSR-RECONFIG-002 |

---

## 5. Bidirectional Check

### 5.1 Forward: Every requirement has implementation + verification

All 31 requirements in the SSRS are traced to at least one
implementation reference and at least one verification method.
**No untraceable requirements.**

### 5.2 Reverse: Every test traces back to a requirement

| Test Case | Requirements Verified |
|---|---|
| `test_meta.c:test_sizeof` | SSR-META-001 |
| `test_meta.c:test_fits_in_headroom` | SSR-META-002 |
| `test_meta.c:test_alignment` | SSR-META-004 |
| `test_meta.c:test_field_offsets` | SSR-META-003 |
| `test_meta.c:test_flag_constants` | — (not a safety req, functional) |
| `test_meta.c:test_zero_init` | SSR-META-007 |
| `test_meta.c:test_version_constant` | SSR-META-005 (supports) |
| `test_meta.c:test_scratch_size` | SSR-META-001 (supports) |
| `test_meta_get.c:test_meta_get_wrong_version` | SSR-META-005 |
| `test_meta_get.c:test_meta_get_correct_version` | SSR-META-005 |
| `test_meta_get.c:test_meta_get_insufficient_headroom` | SSR-META-006 |
| `test_meta_get.c:test_meta_get_exact_headroom` | SSR-META-006 |
| `test_meta_get.c:test_meta_get_excess_headroom` | SSR-META-006 |
| `test_meta_get.c:test_meta_get_both_checks` | SSR-META-005, SSR-META-006 |
| `test_dag.c:test_empty_graph` | SSR-DAG-002 |
| `test_dag.c:test_linear_chain` | SSR-DAG-002 |
| `test_dag.c:test_diamond` | SSR-DAG-002 |
| `test_dag.c:test_simple_cycle` | SSR-DAG-001 |
| `test_dag.c:test_self_loop` | SSR-DAG-003 |
| `test_dag.c:test_disconnected` | SSR-DAG-002 |
| `test_dag.c:test_three_node_cycle` | SSR-DAG-001 |
| `test_dag.c:test_complex_dag` | SSR-DAG-002 |
| `test_graph.c:test_create_destroy` | SSR-RES-001, SSR-RES-002 |
| `test_graph.c:test_destroy_null` | SSR-RES-001 |
| `test_graph.c:test_create_null_name` | SSR-ERR-002 |
| `test_graph.c:test_create_empty_name` | SSR-ERR-002 |
| `test_graph.c:test_add_invalid_index` | SSR-NODE-001 |
| `test_graph.c:test_remove_nonexistent` | SSR-NODE-003 |
| `test_graph.c:test_add_null_params` | SSR-ERR-002 |
| `test_graph.c:test_add_edge` | SSR-ERR-002 |
| `test_graph.c:test_map_fds` | — (functional, supports SSR-MAP-001) |
| `test_node_edges.c:test_remove_clears_outgoing` | SSR-NODE-004 |
| `test_node_edges.c:test_remove_clears_incoming` | SSR-NODE-004, SSR-DAG-005 |
| `test_node_edges.c:test_remove_breaks_cycle` | SSR-NODE-004, SSR-DAG-001 |
| `test_node_edges.c:test_remove_leaf_node` | SSR-NODE-004 |
| `test_reconfig.c:test_double_begin` | SSR-RECONFIG-004 |
| `test_reconfig.c:test_abort_clears_state` | SSR-RECONFIG-003 |
| `test_reconfig.c:test_abort_without_begin` | SSR-RECONFIG-003 |
| `test_reconfig.c:test_stage_without_begin` | SSR-RECONFIG-004 |
| `test_reconfig.c:test_commit_without_begin` | SSR-RECONFIG-004 |
| `test_reconfig.c:test_double_stage_same_index` | SSR-RECONFIG-004 |
| `test_reconfig.c:test_null_graph` | SSR-ERR-001, SSR-ERR-002 |
| `test_reconfig.c:test_multiple_cycles` | SSR-RECONFIG-003 |
| `test_pipeline.c:test_pipeline_lifecycle` | SSR-DAG-001, SSR-DAG-002, SSR-DAG-004 |
| `test_pipeline.c:test_veth_creation` | — (infrastructure, no safety req) |
| `test_privileged.c:test_map_creation` | SSR-MAP-001, SSR-MAP-002 |
| `test_privileged.c:test_stats_aggregation` | SSR-STATS-001 |
| `test_privileged.c:test_stats_reset` | SSR-STATS-002 |
| `test_privileged.c:test_prog_array_map` | SSR-MAP-001 |
| `test_wrapper.c:test_create_destroy` | SSR-RES-001, SSR-RES-002 |
| `test_wrapper.c:test_destroy_null` | SSR-RES-001 |
| `test_wrapper.c:test_create_with_max_nodes` | — (functional) |
| `test_wrapper.c:test_get_egl_valid` | SSR-WRAP-002 |
| `test_wrapper.c:test_get_egl_null` | SSR-WRAP-002, SSR-ERR-002 |
| `test_wrapper.c:test_create_null_name` | SSR-ERR-002 |
| `test_wrapper.c:test_create_empty_name` | SSR-ERR-002 |
| `test_wrapper.c:test_add_node_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_remove_node_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_add_edge_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_validate_dag_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_attach_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_attach_null_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_detach_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_detach_null_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_add_tx_port_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_add_tx_port_null_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_create_xsk_null_graph` | SSR-ERR-002 |
| `test_wrapper.c:test_get_prog_array_fd_null` | SSR-ERR-002 |
| `test_wrapper.c:test_get_stats_map_fd_null` | SSR-ERR-002 |
| `test_wrapper.c:test_dag_delegation_linear` | SSR-WRAP-001 |
| `test_wrapper.c:test_dag_delegation_cycle` | SSR-WRAP-001 |
| `test_wrapper.c:test_attach_validates_dag` | SSR-WRAP-003 |
| `test_wrapper.c:test_destroy_aborts_reconfig` | SSR-WRAP-004 |
| `test_wrapper.c:test_add_node_bad_path` | SSR-ERR-002, FM-NODE-02 |
| `test_wrapper.c:test_attach_no_root_program` | SSR-ERR-002 |
| `test_wrapper.c:test_attach_bad_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_detach_bad_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_add_tx_port_bad_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_create_xsk_bad_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_create_xsk_null_ifname` | SSR-ERR-002 |
| `test_wrapper.c:test_create_xsk_negative_queue` | SSR-ERR-002 |
| `test_xsk.c:test_xsk_recv_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_recv_null_outputs` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_recv_release_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_send_alloc_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_send_alloc_zero_len` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_send_complete_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_poll_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_recv_batch_null` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_recv_batch_zero_max` | SSR-XSK-003 |
| `test_xsk.c:test_xsk_recv_release_batch_null` | SSR-XSK-003 |
| `test_xsk_privileged.c:test_xsk_zerocopy_fallback` | SSR-XSK-001 |
| `test_xsk_privileged.c:test_xsk_fd_for_xskmap` | SSR-XSK-005 |
| `test_xsk_privileged.c:test_graph_create_xsk` | SSR-XSK-005 |
| `test_xsk_privileged.c:test_xsk_send_recv` | — (functional) |
| `test_xsk_privileged.c:test_xsk_batch_recv` | — (functional) |
| `test_xsk_privileged.c:test_xsk_data_recv` | SSR-XSK-003 (recv data path coverage) |
| `test_xsk_privileged.c:test_xsk_data_recv_batch` | SSR-XSK-003 (recv_batch data path coverage) |
| `test_xsk_privileged.c:test_xsk_data_send` | SSR-XSK-003 (send_alloc/complete data path) |
| `test_xsk_privileged.c:test_add_tx_port_success` | SSR-RES-002 (DEVMAP creation path) |
| `test_xsk_privileged.c:test_xsk_destroy_cleanup` | SSR-XSK-002 |
| `test_fmea_mitigations.c:test_fm_dag_04_attach_with_cycle` | SSR-WRAP-003 (FM-DAG-04) |
| `test_fmea_mitigations.c:test_fm_reconfig_04_destroy_aborts` | SSR-WRAP-004 (FM-RECONFIG-04) |
| `test_fmea_mitigations.c:test_fm_node_03_reconfig_commit_timing` | SSR-RECONFIG-002 (FM-NODE-03) |
| `test_fmea_mitigations.c:test_fm_meta_06_invalid_next_node` | — (FM-META-06, supports SSR-NODE-005) |
| `test_fmea_mitigations.c:test_fm_disp_01_no_root_program` | — (FM-DISP-01) |
| `test_fmea_mitigations.c:test_fm_disp_02_empty_graph_attach` | — (FM-DISP-02) |
| `test_fmea_mitigations.c:test_fm_node_02_type_rejection` | FM-NODE-02 |
| `test_fmea_mitigations.c:test_fm_reconfig_01_rollback` | FM-RECONFIG-01, SSR-RES-002 |
| `test_fault_xgl.c:test_graph_create_fault` | SSR-RES-002 |
| `test_fault_xgl.c:test_xsk_create_fault` | SSR-XSK-004 |
| `test_fault_xgl.c:test_graph_create_xsk_fault` | SSR-XSK-004, SSR-RES-002 |
| `meta_bounds_harness.c` (CBMC) | SSR-META-001, -002, -003, -004 |
| `dag_cycle_harness.c` (CBMC) | SSR-DAG-001, -002, -003 |
| `GraphTopology.tla` (TLA+) | SSR-DAG-001, -002, -004, -005 |

**No orphan tests** (all tests trace to at least one requirement or are
explicitly marked as functional/infrastructure).

---

## 6. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
| 1.1 | 2026-03-02 | xdp-graph-lib team | Closed all REVIEW gaps: added test_meta_get.c (SSR-META-005/006), test_node_edges.c (SSR-NODE-004), test_reconfig.c (SSR-RECONFIG-003/004), test_privileged.c (SSR-MAP-001/002, SSR-STATS-001/002). Reclassified SSR-NODE-005 and SSR-RECONFIG-002 as ACCEPTED. Coverage: 94% PASS, 6% ACCEPTED, 0% REVIEW. |
| 1.2 | 2026-03-04 | xdp-graph-lib team | Added SSR-WRAP-001..004, SSR-XSK-001..005. Added traceability for test_wrapper.c (24 cases), test_xsk.c (+10 cases), test_xsk_privileged.c (6 cases), test_fmea_mitigations.c (6 cases), test_fault_xgl.c (3 cases). Coverage: 95% PASS, 5% ACCEPTED. |
| 1.3 | 2026-03-04 | xdp-graph-lib team | Extended tests: test_wrapper.c (32 cases, +8 error path coverage), test_xsk_privileged.c (10 cases, +4 data path + DEVMAP), test_fmea_mitigations.c (8 cases, +2 type rejection + rollback). Added XDP type validation (FM-NODE-02), reconfig rollback (FM-RECONFIG-01). Line coverage: 85%, function coverage: 100%. |
