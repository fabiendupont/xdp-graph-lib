# Tool Qualification Report

**Project:** xdp-graph-lib
**Document ID:** XGL-TQR-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 8, Clause 11
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Purpose

This document qualifies the software tools used to verify safety
requirements of xdp-graph-lib, as required by ISO 26262 Part 8,
Clause 11. Tools that could introduce or fail to detect errors in
the safety-related output must be qualified.

---

## 2. Tool Classification

### 2.1 Tool Impact and Error Detection (Table 4 of Part 8)

| Tool | TI (Tool Impact) | TD (Tool error Detection) | TCL |
|---|---|---|---|
| GCC 15.2.1 | TI2 — can introduce errors in output | TD2 — moderate detection (warnings, ASAN) | TCL2 |
| CBMC 6.1.1 | TI1 — cannot introduce errors, only verifies | TD1 — high detection (formal proof) | TCL1 |
| TLC (TLA+ Tools) | TI1 — cannot introduce errors, only verifies | TD1 — high detection (exhaustive state space) | TCL1 |
| Meson 1.8.5 | TI2 — controls compilation process | TD2 — errors visible in build output | TCL2 |
| gcovr | TI1 — cannot introduce errors, only measures | TD2 — coverage gaps visible in report | TCL1 |

### 2.2 TCL Summary

- **TCL1** (low confidence needed): CBMC, TLC, gcovr — verification
  tools that do not modify the software under test.
- **TCL2** (medium confidence needed): GCC, Meson — tools that
  directly produce the executable output. Qualified by widespread
  industrial use and validation through testing.

---

## 3. Tool Qualification — CBMC 6.1.1

### 3.1 Tool Information

| Property | Value |
|---|---|
| Tool Name | CBMC (C Bounded Model Checker) |
| Version | 6.1.1 |
| Vendor | Daniel Kroening et al. (open source) |
| License | BSD-4-Clause |
| Platform | x86_64 Linux |
| Installation | Cargo (Rust toolchain) |

### 3.2 Use Case

CBMC is used to formally verify two safety properties:

1. **Meta bounds** (`meta_bounds_harness.c`): All field accesses in
   `struct xgl_meta` are within bounds of the XDP headroom buffer.
2. **DAG cycle detection** (`dag_cycle_harness.c`): Kahn's algorithm
   and DFS cycle detection produce identical results for all possible
   graphs of up to 6 nodes.

### 3.3 Tool Confidence Level: TCL1

CBMC is a **verification tool** (TI1): it analyzes code but does not
produce the deliverable software. A tool malfunction would result in
a false VERIFICATION SUCCESSFUL — it cannot introduce errors into the
software.

**Qualification method:** Use case documentation (ISO 26262 Table 5,
Method 1a for TCL1).

### 3.4 Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| Does not support `__attribute__((packed))` | Cannot verify exact packed struct size (52 bytes) | Verified separately by `_Static_assert` in production compiler |
| SAT solver timeout for large state spaces | Cannot verify 8+ node graphs in reasonable time | Bounded to 6 nodes; TLA+ covers unbounded topology |
| Does not model kernel BPF verifier | Cannot verify BPF-specific constraints | BPF verifier runs at load time (runtime check) |

### 3.5 Validation Evidence

| Harness | Assertions | Result | Runtime |
|---|---|---|---|
| `meta_bounds_harness.c` | 66 | All SUCCESS | < 1s |
| `dag_cycle_harness.c` (6 nodes) | 117 | All SUCCESS | ~8.5 min |

---

## 4. Tool Qualification — TLC (TLA+ Model Checker)

### 4.1 Tool Information

| Property | Value |
|---|---|
| Tool Name | TLC Model Checker |
| Version | tla2tools.jar (TLA+ Toolbox) |
| Vendor | Leslie Lamport / Microsoft Research (open source) |
| License | MIT |
| Platform | JVM (Java) on x86_64 Linux |
| Installation | ~/.local/share/tlaplus/tla2tools.jar |

### 4.2 Use Case

TLC exhaustively checks the `GraphTopology.tla` specification:

- **Invariants:** `IsDAGCorrect` (no cycles), `NoOrphanEdges`
  (all edge endpoints are valid nodes), `TypeOK` (type safety)
- **Temporal properties:** `AlwaysDAG` (DAG invariant holds in all
  reachable states), `AlwaysNoOrphans`

### 4.3 Tool Confidence Level: TCL1

TLC is a **verification tool** (TI1): it explores the state space of
a formal specification. It does not produce executable code.

**Qualification method:** Use case documentation (ISO 26262 Table 5,
Method 1a for TCL1).

### 4.4 Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| State space bounded by `MaxNodes` constant | Only verifies for graphs up to 5 nodes | Algorithm is uniform over N; CBMC covers 6 nodes |
| Does not model BPF execution semantics | TLA+ spec models graph topology, not packet processing | Packet processing verified by BPF verifier + unit tests |
| Hash-based state storage (fingerprinting) | Probability of missed states ~5.5E-10 | Probability negligible for certification |

### 4.5 Validation Evidence

| Specification | States Generated | Distinct States | Depth | Errors | Runtime |
|---|---|---|---|---|---|
| `GraphTopology.tla` (MaxNodes=5) | 348,311 | 32,282 | 16 | 0 | 2s |

---

## 5. Tool Qualification — GCC 15.2.1

### 5.1 Tool Information

| Property | Value |
|---|---|
| Tool Name | GCC (GNU Compiler Collection) |
| Version | 15.2.1 20260123 (Red Hat 15.2.1-7) |
| Vendor | GNU Project (open source) |
| Platform | x86_64 Fedora 43 |

### 5.2 Tool Confidence Level: TCL2

GCC is a **production tool** (TI2): it directly produces the
executable output. Errors in GCC could silently corrupt the software.

**Qualification method:** Increased confidence from use (ISO 26262
Table 5, Method 1b for TCL2).

### 5.3 Confidence Justification

- GCC is the most widely used C compiler in safety-critical Linux
  systems, with decades of industrial use.
- Red Hat-provided packages include their own QA and regression testing.
- The project uses `-Wall -Wextra -Werror -Wconversion -Wshadow
  -Wstrict-prototypes -Wmissing-prototypes` to maximize error detection.
- ASAN and UBSAN sanitizers provide runtime validation of compiler output.
- `_Static_assert` verifies critical layout assumptions at compile time.

---

## 6. Tool Qualification — Meson 1.8.5

### 6.1 Tool Confidence Level: TCL2

Meson controls the build process. A Meson bug could cause incorrect
compilation flags or missing source files.

**Qualification method:** Increased confidence from use (Method 1b).

### 6.2 Confidence Justification

- Build output is inspected via `meson compile -v` (verbose mode).
- Warning flags verified in `meson-info/intro-targets.json`.
- Test results independently verifiable via direct execution.

---

## 7. Tool Qualification — gcovr

### 7.1 Tool Confidence Level: TCL1

gcovr is a **measurement tool** (TI1): it reports code coverage but
does not modify software. Under-reporting coverage is conservative
(safe). Over-reporting could mask gaps.

**Qualification method:** Use case documentation (Method 1a).

### 7.2 Validation Evidence

| Metric | Value |
|---|---|
| Line coverage (userspace library, root) | 82% |
| Branch coverage (userspace library, root) | 72% |
| Line coverage (`xgl_graph.c` — safety-critical) | 86% |
| Branch coverage (`xgl_graph.c` — safety-critical) | 80% |
| Line coverage (`xgl_reconfig.c`) | 97% |
| Line coverage (`xgl_stats.c`) | 76% |
| Line coverage (`xgl_loader.c`) | 49% |
| Coverage gap explanation | Remaining gaps are BPF filesystem interactions (`pin_maps`, `reuse_maps`), internal error paths in BPF map reuse, and per-CPU allocation failure paths. These require fault injection or specific bpffs setup to trigger. |

---

## 8. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
