# MISRA C Compliance Report

**Project:** xdp-graph-lib
**Document ID:** XGL-MISRA-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 6, Clause 5.4.3
**Standard:** MISRA C:2012 (informative, adapted for BPF constraints)
**Status:** Initial Assessment

---

## 1. Scope

MISRA C:2012 compliance is **recommended** (not required) for ASIL-A
by ISO 26262 Part 6, Table 1. This report documents the coding
standard approach and known deviations.

---

## 2. Static Analysis Results

### 2.1 cppcheck (v2.19.1)

Analysis command:
```
cppcheck --enable=all --std=c11 -I include \
         --suppress=missingIncludeSystem src/userspace/
```

| Category | Count | Details |
|---|---|---|
| Errors | 0 | — |
| Warnings | 0 | — |
| Style suggestions | 5 | See deviations below |

### 2.2 GCC Warnings

Compiled with `-Wall -Wextra -Werror -Wconversion -Wshadow
-Wstrict-prototypes -Wmissing-prototypes`.

| Category | Count |
|---|---|
| Errors | 0 |
| Warnings | 0 (all treated as errors) |

---

## 3. Known Deviations

### 3.1 `__attribute__((packed, aligned(4)))`

**MISRA Rule 1.2:** Not a C standard feature.

**Justification:** Required for cross-domain struct layout agreement
between BPF and userspace. The struct layout is verified by
`_Static_assert` and CBMC. No portable alternative exists for
controlling struct packing.

### 3.2 Statement expressions (`({...})`)

**MISRA Rule 1.2:** GCC extension.

**Justification:** Used in BPF macros (`XGL_META_GET`, `XGL_META_ALLOC`,
`XGL_SCRATCH_GET`) which must return a value from a multi-statement
expansion. Required by the BPF programming model. These macros are
only used in BPF code, not in the userspace library.

### 3.3 `__builtin_memset` in BPF macros

**MISRA Rule 1.2:** Compiler builtin.

**Justification:** Required in BPF context — standard `memset` is not
available in the BPF execution environment. The BPF verifier validates
the call at load time.

### 3.4 `system()` in integration tests

**MISRA Rule 21.8:** Use of `system()` is prohibited.

**Justification:** Used only in test code (`test_pipeline.c`) to create
veth pairs via `ip link` commands. Not present in the library itself.

### 3.5 `const` parameter suggestions

cppcheck suggests `const` for `xgl_graph_validate_dag(g)`,
`xgl_graph_get_prog_array_fd(g)`, `xgl_graph_get_stats_map_fd(g)`.

**Status:** Accepted as style improvement for future release. Not
a safety issue — these functions do not modify the graph.

---

## 4. Compliance Summary

| Scope | MISRA Compliance |
|---|---|
| Userspace library (`src/userspace/`) | Compliant with documented deviations |
| Public headers (`include/xgl/`) | Deviations for packed attribute and GCC extensions |
| BPF code (`src/bpf/`) | Out of scope — BPF requires non-standard extensions |
| Test code (`tests/`) | Out of scope — test code is not safety-critical |

---

## 5. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial assessment |
