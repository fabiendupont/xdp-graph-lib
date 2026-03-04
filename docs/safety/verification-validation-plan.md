# Verification and Validation Plan

**Project:** xdp-graph-lib
**Document ID:** XGL-VVP-001
**Version:** 1.1
**Date:** 2026-03-04
**Classification:** ISO 26262 Part 6, Clause 9
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Purpose

This document defines the verification and validation strategy for
xdp-graph-lib, specifying what is tested, how, by whom, and the
pass/fail criteria for each verification activity.

---

## 2. Verification Methods

ISO 26262 Part 6, Table 7 recommends these methods for ASIL-A:

| Method | ISO Recommendation | xdp-graph-lib Status |
|---|---|---|
| Requirements-based testing | Highly recommended | Implemented (RTM traces all 40 SSRs to tests) |
| Interface testing | Highly recommended | Implemented (input validation tests for all public APIs) |
| Fault injection testing | Recommended (ASIL-A) / Highly recommended (ASIL-B) | Implemented (LD_PRELOAD calloc fault injection, 3 cases) |
| Back-to-back testing | Recommended | Implemented (CBMC: Kahn vs DFS equivalence) |
| Static analysis | Highly recommended | Implemented (compiler warnings, CBMC) |
| Code review | Highly recommended | Applied to all files |
| Formal verification | Recommended | Implemented (CBMC + TLA+) |

---

## 3. Test Suites

### 3.1 Unit Tests (Unprivileged)

| Suite | File | Cases | Covers | Pass Criteria |
|---|---|---|---|---|
| test_meta | `tests/unit/test_meta.c` | 8 | SSR-META-001..004, 007 | All assertions pass, exit code 0 |
| test_meta_get | `tests/unit/test_meta_get.c` | 6 | SSR-META-005, 006 | All assertions pass, exit code 0 |
| test_dag | `tests/unit/test_dag.c` | 8 | SSR-DAG-001..003 | All assertions pass, exit code 0 |
| test_graph | `tests/unit/test_graph.c` | 9 | SSR-NODE-001..003, SSR-RES-001, SSR-ERR-001..002 | All assertions pass, exit code 0 |
| test_node_edges | `tests/unit/test_node_edges.c` | 4 | SSR-NODE-004, SSR-DAG-005 | All assertions pass, exit code 0 |
| test_reconfig | `tests/unit/test_reconfig.c` | 8 | SSR-RECONFIG-003..004 | All assertions pass, exit code 0 |
| test_wrapper | `tests/unit/test_wrapper.c` | 32 | SSR-WRAP-001..004, SSR-ERR-002, FM-NODE-02 | All assertions pass, exit code 0 |
| test_xsk | `tests/unit/test_xsk.c` | 16 | SSR-XSK-003 | All assertions pass, exit code 0 |

### 3.2 Integration Tests (Privileged)

| Suite | File | Cases | Covers | Pass Criteria |
|---|---|---|---|---|
| test_pipeline | `tests/integration/test_pipeline.c` | 3 | SSR-DAG-001..002, 004 | All pass or SKIP (non-root) |
| test_privileged | `tests/integration/test_privileged.c` | 9 | SSR-MAP-001..002, SSR-STATS-001..002 | All pass or SKIP (non-root) |
| test_xsk_privileged | `tests/integration/test_xsk_privileged.c` | 10 | SSR-XSK-001, 002, 005 + data path coverage | All pass or SKIP (non-root) |
| test_fmea_mitigations | `tests/integration/test_fmea_mitigations.c` | 8 | SSR-WRAP-003..004, FM-DAG-04, FM-RECONFIG-04, FM-NODE-03, FM-DISP-01..02, FM-NODE-02, FM-RECONFIG-01 | All pass or SKIP (non-root) |

### 3.2a Fault Injection Tests

| Suite | File | Cases | Covers | Pass Criteria |
|---|---|---|---|---|
| test_fault_xgl | `tests/fault/test_fault_xgl.c` | 3 | SSR-XSK-004, SSR-RES-002 | Exit code 0 (baseline), no crash under LD_PRELOAD sweep |

### 3.3 Formal Verification

| Harness | File | Assertions | Covers | Pass Criteria |
|---|---|---|---|---|
| Meta bounds | `verification/cbmc/meta_bounds_harness.c` | 66 | SSR-META-001..004 | VERIFICATION SUCCESSFUL |
| DAG cycle | `verification/cbmc/dag_cycle_harness.c` | 117 | SSR-DAG-001..003 | VERIFICATION SUCCESSFUL |
| Graph topology | `verification/tlaplus/GraphTopology.tla` | 3 invariants, 2 properties | SSR-DAG-001..005 | No error, 0 states left on queue |

### 3.4 Sanitizer Builds

| Build | Configuration | Pass Criteria |
|---|---|---|
| ASAN | `meson setup -Db_sanitize=address,undefined` | All tests pass, no ASAN/UBSAN errors |
| Coverage | `meson setup -Db_coverage=true` | Coverage report generated |

---

## 4. Test Execution Procedure

### 4.1 Standard (Unprivileged)

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir
```

Expected: All unit tests pass, integration/fault tests pass or SKIP.

### 4.1a Unit Tests Only

```sh
meson test -C builddir --suite unit
```

Expected: 8 test binaries, all pass.

### 4.1b Fault Injection Sweep

```sh
cd builddir
for N in 0 1 2 3 4 5; do
    FAULT_CALLOC_AFTER=$N LD_PRELOAD=./libfault_alloc.so ./test_fault_xgl
done
```

Expected: Each run exits 0 (no crash, no leak).

### 4.2 Sanitizer

```sh
meson setup builddir-asan -Db_sanitize=address,undefined
meson test -C builddir-asan
```

Expected: All tests pass, no sanitizer output.

### 4.3 Privileged (Root)

```sh
sudo meson test -C builddir
```

Expected: test_privileged, test_pipeline, test_xsk_privileged, and
test_fmea_mitigations BPF/XSK tests run (instead of SKIP).

### 4.4 CBMC

```sh
cbmc --bounds-check --pointer-check \
     verification/cbmc/meta_bounds_harness.c -I include
cbmc --bounds-check --unwinding-assertions --unwind 7 \
     verification/cbmc/dag_cycle_harness.c -I include
```

Expected: VERIFICATION SUCCESSFUL for both.

### 4.5 TLC

```sh
cd verification/tlaplus
java -jar tla2tools.jar -config GraphTopology.cfg GraphTopology.tla
```

Expected: "Model checking completed. No error has been found."

### 4.6 Coverage

```sh
meson setup builddir-cov -Db_coverage=true
meson compile -C builddir-cov
sudo meson test -C builddir-cov
sudo chown -R $USER builddir-cov
# Add fault injection coverage
for N in 0 1 2 3 4 5; do
    FAULT_CALLOC_AFTER=$N \
        LD_PRELOAD=./builddir-cov/tests/fault/libfault_alloc.so \
        ./builddir-cov/tests/fault/test_fault_xgl
done
gcovr --root . --filter 'src/userspace/' builddir-cov
```

Target: >80% line coverage for safety-critical modules.

**Achieved:** 85% line coverage, 100% function coverage.

| File | Lines | Functions |
|---|---|---|
| `xgl_graph.c` | 84% (135/160) | 100% (14/14) |
| `xgl_xsk.c` | 86% (136/158) | 100% (11/11) |
| **Total** | **85% (271/318)** | **100% (25/25)** |

Uncovered lines are kernel error paths (mmap failure, UMEM
reservation failure, sendto error), hardware-dependent paths
(XDP zerocopy success), and BPF attach success paths that
require a fully loaded XDP pipeline. These are documented as
acceptable residual coverage gaps.

---

## 5. Pass/Fail Criteria

### 5.1 Release Criteria

A release is acceptable for ASIL-B when ALL of:

1. All unit tests pass (0 failures)
2. All integration tests pass or SKIP with documented reason
3. ASAN/UBSAN build passes with 0 findings (unprivileged + privileged)
4. CBMC verifies all harnesses (VERIFICATION SUCCESSFUL)
5. TLC model checks all invariants (0 errors)
6. Traceability matrix shows 0 REVIEW items
7. FMEA has no unmitigated high-risk items (RPN >= 10)
8. Line coverage >= 80% for safety-critical modules
9. Fault injection sweep (FAULT_CALLOC_AFTER=0..5) passes with 0 crashes

### 5.2 Regression Criteria

Any code change must:

1. Pass all existing tests
2. Not reduce code coverage
3. Not introduce new ASAN/UBSAN findings
4. Not break CBMC or TLC verification

---

## 6. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Developer | Write code, unit tests, run local verification |
| Safety Engineer | Review FMEA, approve safety requirements |
| Independent Reviewer | Review code changes, verify traceability |
| CI System | Run automated test suite on every commit |

---

## 7. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
| 1.1 | 2026-03-04 | xdp-graph-lib team | Added test_wrapper, test_xsk extensions, test_xsk_privileged, test_fmea_mitigations, test_fault_xgl. Updated fault injection from "Partial" to "Implemented". |
| 1.2 | 2026-03-04 | xdp-graph-lib team | Updated test counts (test_wrapper: 32, test_xsk_privileged: 10, test_fmea: 8). Added data path coverage tests, add_tx_port test, reconfig rollback test, XDP type rejection test. Coverage: 85% line, 100% function. Updated release criteria to ASIL-B with coverage and fault injection requirements. Added coverage procedure with fault injection accumulation. |
