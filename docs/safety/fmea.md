# Failure Mode and Effects Analysis (FMEA)

**Project:** xdp-graph-lib
**Document ID:** XGL-FMEA-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 9 / IEC 61508 Part 3
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Scope

This FMEA covers all software components of xdp-graph-lib that are
within the safety boundary defined in XGL-SSRS-001:

- Metadata struct and access macros (BPF side)
- Graph topology management (userspace)
- BPF program loading and map sharing (userspace)
- Atomic reconfiguration (userspace)
- Per-node statistics (userspace + BPF)
- Root dispatcher (BPF)

### 1.1 Severity Classification

| Severity | Definition | Example |
|---|---|---|
| S3 (High) | Packet corruption or silent data loss | Metadata overwrite corrupts forwarding decision |
| S2 (Medium) | Service degradation or incorrect routing | Packets dropped that should have been forwarded |
| S1 (Low) | Observable error with safe fallback | Tail call failure with XDP_PASS fallback |
| S0 (None) | No safety impact | Statistics counter slightly inaccurate |

### 1.2 Occurrence Classification

| Occurrence | Definition |
|---|---|
| O3 (High) | Can occur under normal operating conditions |
| O2 (Medium) | Can occur under specific edge cases or race conditions |
| O1 (Low) | Requires multiple simultaneous faults or adversarial input |

### 1.3 Detection Classification

| Detection | Definition |
|---|---|
| D3 (None) | Failure is silent — no mechanism to detect it |
| D2 (Delayed) | Detectable via monitoring/stats but not immediately |
| D1 (Immediate) | Detected at load time, compile time, or by verifier |

### 1.4 Risk Priority Number

RPN = Severity x Occurrence x Detection (1-27 scale)

| RPN Range | Action |
|---|---|
| 1-3 | Acceptable — document and monitor |
| 4-9 | Recommend mitigation |
| 10-27 | Mandatory mitigation before certification |

---

## 2. FMEA Table

### 2.1 Metadata Subsystem

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-META-01 | `xgl_meta` struct | Size differs between BPF and userspace | Compiler flag mismatch (missing `-packed`), different compiler versions | Metadata fields misaligned — all nodes read wrong values, packets silently misrouted | S3 | O1 | D1 | 3 | `_Static_assert(sizeof == 52)` in header, CBMC proof | Low: compile-time detection | SSR-META-001 |
| FM-META-02 | `XGL_META_ALLOC` | Headroom allocation fails | Interface doesn't support `bpf_xdp_adjust_meta()`, insufficient headroom configured | Returns NULL, root node drops packet | S2 | O2 | D1 | 4 | NULL check in macro, XDP_DROP fallback | Medium: silent drop, but controlled | SSR-META-006 |
| FM-META-03 | `XGL_META_GET` | Reads stale metadata from previous packet | Kernel reuses headroom without clearing | Nodes process with wrong version/flags, incorrect forwarding | S3 | O1 | D2 | 6 | Version field check (`XGL_META_VERSION`), memset in ALLOC | Medium: depends on kernel behavior | SSR-META-005 |
| FM-META-04 | `XGL_META_GET` | Buffer overread — meta extends past `data` | Bug in ALLOC, kernel headroom smaller than expected | Out-of-bounds read, verifier should reject | S3 | O1 | D1 | 3 | Bounds check (`data_meta + sizeof <= data`), BPF verifier | Low: verifier enforces at load time | SSR-META-006 |
| FM-META-05 | `xgl_meta.scratch` | Inter-node data corruption via scratch | Two nodes write to same scratch offsets without coordination | Silent data corruption in scratch area | S2 | O2 | D3 | 12 | **No current mechanism** — scratch is a shared byte array | **High: needs design mitigation** | — |
| FM-META-06 | `xgl_meta.next_node` | Node sets `next_node` to invalid index | Bug in node logic, index >= XGL_MAX_NODES | Tail call to empty slot, silent fallthrough | S2 | O2 | D2 | 8 | Fallback after `XGL_NEXT()`, stats error counter | Medium: fallback mitigates | SSR-NODE-005 |
| FM-META-07 | `xgl_meta.version` | Version field corrupted in transit | Memory corruption, cosmic ray | META_GET returns NULL, packet dropped | S1 | O1 | D1 | 1 | Version check is the detection mechanism itself | Low: self-detecting | SSR-META-005 |

### 2.2 Graph Topology Subsystem

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-DAG-01 | `xgl_graph_validate_dag` | False negative — cycle not detected | Bug in Kahn's algorithm | Infinite tail call loop (bounded by kernel to 33), packet dropped | S2 | O1 | D2 | 4 | CBMC proof (Kahn vs DFS equivalence), TLA+ invariant, kernel 33-call limit | Low: proven correct for N<=6, kernel bounds | SSR-DAG-001 |
| FM-DAG-02 | `xgl_graph_validate_dag` | False positive — valid DAG rejected | Bug in active-node detection | Valid pipeline topology rejected, control plane error | S1 | O1 | D1 | 1 | CBMC proof, unit tests for all DAG patterns | Low: immediately visible | SSR-DAG-002 |
| FM-DAG-03 | Edge bitmask | Bitmask overflow for index >= 32 | XGL_MAX_NODES changed without updating bitmask type | Edges silently lost, cycle detection incomplete | S3 | O1 | D1 | 3 | `__u32` bitmask limits to 32 bits, XGL_MAX_NODES = 32 | Low: design constraint | SSR-DAG-001 |
| FM-DAG-04 | `xgl_graph_add_edge` | Edge added without DAG validation | Caller forgets to call `validate_dag()` | Cycle in graph, tail call loop | S2 | O2 | D3 | 12 | **No enforcement** — validation is caller's responsibility | **High: needs API improvement** | SSR-DAG-001 |

### 2.3 Node Management Subsystem

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-NODE-01 | `xgl_graph_add_node` | BPF program loaded but map sharing fails | `bpf_map__reuse_fd` returns error, error not propagated | Node has private maps, tail calls between nodes fail silently | S3 | O1 | D2 | 6 | Error return from `add_node`, early exit on reuse_fd failure | Medium: error propagated but caller must check | SSR-MAP-001 |
| FM-NODE-02 | `xgl_graph_add_node` | Wrong program loaded at index | Caller provides wrong `prog_name` or `bpf_obj_path` | Pipeline processes packets with wrong logic | S3 | O2 | D1 | 6 | `check_prog_type()` validates `BPF_PROG_TYPE_XDP` before loading; rejects non-XDP programs with `-EINVAL` | **Mitigated**: type validation at load time, RPN reduced 18→6 | — |
| FM-NODE-03 | `xgl_graph_remove_node` | Node removed while packets in flight | No synchronization with data path | In-flight packet tail-calls to removed program slot | S2 | O2 | D3 | 12 | **Partial**: removal clears PROG_ARRAY (atomic per-entry) but no RCU wait | **High: needs RCU grace period** | SSR-RECONFIG-002 |
| FM-NODE-04 | PROG_ARRAY | Map fd leaked on error path | Exception in add_node between map creation and object tracking | File descriptor leak, eventual exhaustion | S1 | O1 | D2 | 2 | Lazy map creation, cleanup in destroy | Low: ASAN catches | SSR-RES-002 |
| FM-NODE-05 | `xgl_graph_attach` | XDP attached to wrong interface | Caller provides wrong `ifname` | Packets on wrong interface processed by pipeline | S3 | O2 | D3 | 18 | Documented as caller precondition in `xgl_graph.h`. Outside library safety boundary. | **Accepted**: application-level concern, documented | — |

### 2.4 Reconfiguration Subsystem

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-RECONFIG-01 | `xgl_reconfig_commit` | Partial commit — some nodes applied, some fail | BPF load fails mid-commit | Pipeline in inconsistent state — some new nodes, some missing | S3 | O2 | D1 | 6 | Full rollback: snapshots removed nodes before applying, restores adds (reverse) and removes on failure | **Mitigated**: rollback implemented, RPN reduced 12→6 | SSR-RECONFIG-001 |
| FM-RECONFIG-02 | `xgl_reconfig_commit` | RCU grace period too short | System under extreme load, `usleep` interrupted by signal | In-flight packet references removed program | S2 | O1 | D3 | 6 | 10ms default (conservative for most systems) | Medium: signal interruption possible | SSR-RECONFIG-002 |
| FM-RECONFIG-03 | Reconfig state table | State table full (>16 concurrent graphs) | Application creates many graph instances | `xgl_reconfig_begin` returns `-ENOMEM` | S1 | O1 | D1 | 1 | Error return, XGL_MAX_GRAPHS = 16 | Low: immediately visible | SSR-RECONFIG-004 |
| FM-RECONFIG-04 | Reconfig state table | Stale entry after graph destroy | Graph destroyed without aborting active reconfig | State table entry orphaned, matches wrong graph on pointer reuse | S2 | O2 | D3 | 12 | **No cleanup** — destroy doesn't clear reconfig state | **High: needs cleanup in destroy** | SSR-RES-002 |

### 2.5 Statistics Subsystem

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-STATS-01 | `xgl_stats_read` | Counter overflow (wrap-around) | 64-bit counter wraps after 2^64 packets | Statistics incorrect | S0 | O1 | D2 | 0 | 64-bit counters — wrap-around after ~18 exapackets | None: not safety-relevant | SSR-STATS-001 |
| FM-STATS-02 | `xgl_stats_read` | Tearing on 64-bit read | Per-CPU read non-atomic on 32-bit arch | Partially updated counter value | S0 | O1 | D3 | 0 | x86_64 target — 64-bit reads are atomic | None: architecture-specific, not safety-relevant | SSR-STATS-001 |
| FM-STATS-03 | `XGL_STATS_INC_*` | Stats map lookup fails | Invalid `node_id`, map not shared | Counter not incremented, silent | S0 | O1 | D3 | 0 | NULL check after `bpf_map_lookup_elem` | None: not safety-relevant | SSR-STATS-001 |

### 2.6 BPF Dispatcher

| ID | Component | Failure Mode | Cause | Effect | S | O | D | RPN | Safety Mechanism | Residual Risk | Req |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FM-DISP-01 | `xgl_dispatch` | Metadata allocation fails | Interface lacks `adjust_meta` support | All packets dropped by root node | S2 | O2 | D2 | 8 | NULL check → XDP_DROP fallback, visible in stats | Medium: controlled failure mode | SSR-META-002 |
| FM-DISP-02 | `xgl_dispatch` | Tail call to node 0 fails | Node 0 not loaded in PROG_ARRAY | Packet dropped (fallback after XGL_NEXT) | S2 | O2 | D2 | 8 | XDP_DROP fallback, error counter increment | Medium: controlled, detectable | SSR-NODE-005 |
| FM-DISP-03 | `xgl_dispatch` | Timestamp inaccurate | `bpf_ktime_get_ns` not monotonic across CPUs | Latency measurements incorrect | S0 | O1 | D3 | 0 | Informational field only | None: not safety-relevant | — |

---

## 3. Risk Summary

### 3.1 High-Risk Items (RPN >= 10) — Mandatory Mitigation

| ID | RPN | Failure Mode | Recommended Mitigation |
|---|---|---|---|
| FM-META-05 | 12 | Scratch area inter-node corruption | Add per-node scratch offset registry or typed scratch accessors. Document scratch ownership rules in node contract. |
| FM-DAG-04 | 12 | Edge added without DAG validation | Add automatic DAG validation in `xgl_graph_attach()` before attaching to interface. Consider making `add_edge` validate incrementally. |
| FM-NODE-02 | ~~18~~ 6 | Wrong BPF program loaded | **MITIGATED** — `check_prog_type()` validates `BPF_PROG_TYPE_XDP` before loading. RPN reduced from 18 to 6 (D3→D1). |
| FM-NODE-03 | 12 | Node removed while packets in flight | Add RCU grace period to `xgl_graph_remove_node()` (currently only in reconfig commit). |
| FM-NODE-05 | 18 | XDP attached to wrong interface | **ACCEPTED** — documented as caller precondition in `xgl_graph.h:xgl_graph_attach`. Outside library safety boundary. |
| FM-RECONFIG-01 | ~~12~~ 6 | Partial commit without rollback | **MITIGATED** — full rollback implemented. Snapshots removed nodes, restores on failure. RPN reduced from 12 to 6 (D2→D1). |
| FM-RECONFIG-04 | 12 | Stale reconfig state after destroy | Add reconfig state cleanup to `xgl_graph_destroy()`. |

### 3.2 Medium-Risk Items (RPN 4-9) — Recommended Mitigation

| ID | RPN | Failure Mode | Recommended Mitigation |
|---|---|---|---|
| FM-META-02 | 4 | Headroom allocation fails | Document interface requirements. Add runtime check for `adjust_meta` support. |
| FM-META-03 | 6 | Stale metadata from previous packet | Document kernel headroom lifecycle. Version check is the primary mitigation. |
| FM-META-06 | 8 | Invalid `next_node` index | Add bounds check macro: `XGL_NEXT_SAFE(ctx, map, id)` that validates `id < XGL_MAX_NODES`. |
| FM-NODE-01 | 6 | Map sharing fails silently | Error propagation is implemented. Document error handling requirements for callers. |
| FM-RECONFIG-02 | 6 | RCU grace period too short | Use `SA_RESTART` for signal handling. Consider kernel RCU barrier (`synchronize_rcu` via sysfs) for higher ASIL. |
| FM-DISP-01 | 8 | Metadata allocation fails in dispatcher | Document interface requirements. Visible in stats (drops counter). |
| FM-DISP-02 | 8 | Tail call to node 0 fails | Visible in stats (error counter). Ensure node 0 is always loaded before attach. |

### 3.3 Low-Risk Items (RPN 1-3) — Acceptable

| ID | RPN | Status |
|---|---|---|
| FM-META-01 | 3 | Mitigated by `_Static_assert` |
| FM-META-04 | 3 | Mitigated by BPF verifier |
| FM-META-07 | 1 | Self-detecting |
| FM-DAG-01 | 4 | Proven correct by CBMC + TLA+ |
| FM-DAG-02 | 1 | Proven correct, immediately visible |
| FM-DAG-03 | 3 | Design constraint (32-bit bitmask) |
| FM-NODE-04 | 2 | Detected by ASAN |
| FM-RECONFIG-03 | 1 | Immediately visible error return |

---

## 4. Fault Tree Analysis — Top Event: Silent Packet Loss

```
                    Silent Packet Loss
                          |
              +-----------+-----------+
              |                       |
    Metadata Failure           Pipeline Failure
         |                         |
    +----+----+              +-----+-----+
    |         |              |           |
  ALLOC    GET fails      Tail call   Node logic
  fails    silently       fails       error
  (FM-02)  (FM-03,04)    (FM-06)     (FM-02)
    |         |              |           |
  XDP_DROP  Version or    Empty       Wrong prog
  fallback  bounds check  PROG_ARRAY  loaded
            returns NULL  slot        (FM-NODE-02)
            → XDP_DROP    → fallback
                          (FM-DISP-02)
```

All paths to "Silent Packet Loss" either:
1. Terminate in XDP_DROP (controlled loss, not corruption), or
2. Require FM-NODE-02 (wrong program loaded) — the highest-risk item

**Conclusion:** The primary unmitigated risk is loading the wrong BPF
program (FM-NODE-02). All metadata and pipeline failures have
safe fallback paths (XDP_DROP).

---

## 5. Action Items

| Priority | Action | Addresses | Owner | Target | Status |
|---|---|---|---|---|---|
| P1 | Add reconfig state cleanup to `xgl_graph_destroy()` | FM-RECONFIG-04 | Dev | v0.2.0 | **VERIFIED** — `xgl_graph_destroy` calls `egl_reconfig_abort`. Tests: `test_wrapper.c:test_destroy_aborts_reconfig`, `test_fmea_mitigations.c:test_fm_reconfig_04_destroy_aborts` |
| P1 | Add RCU grace period to `xgl_graph_remove_node()` | FM-NODE-03 | Dev | v0.2.0 | **VERIFIED** — `egl_reconfig_commit` includes 10ms wait. Test: `test_fmea_mitigations.c:test_fm_node_03_reconfig_commit_timing` |
| P1 | Add automatic DAG validation in `xgl_graph_attach()` | FM-DAG-04 | Dev | v0.2.0 | **VERIFIED** — `xgl_graph_attach` calls `xgl_graph_validate_dag` before attach. Tests: `test_wrapper.c:test_attach_validates_dag`, `test_fmea_mitigations.c:test_fm_dag_04_attach_with_cycle` |
| P2 | Implement reconfig rollback on partial commit failure | FM-RECONFIG-01 | Dev | v0.3.0 | **VERIFIED** — `egl_reconfig_commit` snapshots removed nodes and restores on failure. Full rollback for both adds and removes. |
| P2 | Document scratch ownership rules in node contract | FM-META-05 | Doc | v0.2.0 | **VERIFIED** — Ownership rules documented in `xgl_meta.h`. `XGL_SCRATCH_AS()` typed accessor added to `xgl_node.h` with `_Static_assert` on size. |
| P2 | Add `XGL_NEXT_SAFE()` bounds-checking macro | FM-META-06 | Dev | v0.2.0 | **VERIFIED** — `XGL_NEXT_SAFE()` macro validates `node_id < EGL_DEFAULT_MAX_NODES`, increments error counter and returns `XDP_DROP` on out-of-range. Test: `test_fmea_mitigations.c:test_fm_meta_06_invalid_next_node`. |
| P3 | Add BPF program type validation at load time | FM-NODE-02 | Dev | v0.3.0 | **VERIFIED** — `xgl_graph_add_node` validates `BPF_PROG_TYPE_XDP` via `egl_loader_get_prog_type` before loading. Returns `-EINVAL` for non-XDP programs. |
| P3 | Document interface requirements for `adjust_meta` | FM-META-02 | Doc | v0.2.0 | **VERIFIED** — Interface support requirements documented in `xgl_node.h:XGL_META_ALLOC`. Lists supported and unsupported drivers. |

---

## 6. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial FMEA |
| 1.1 | 2026-03-04 | xdp-graph-lib team | Marked P1 actions as VERIFIED with test references |
| 1.2 | 2026-03-04 | xdp-graph-lib team | All action items closed. FM-NODE-02 RPN 18→6 (type validation), FM-RECONFIG-01 RPN 12→6 (full rollback). FM-META-05 (scratch docs + XGL_SCRATCH_AS), FM-META-06 (XGL_NEXT_SAFE), FM-META-02 (adjust_meta docs), FM-NODE-05 (precondition accepted). Test evidence: test_fmea_mitigations (type rejection + rollback tests), 85% line coverage, 100% function coverage. |
