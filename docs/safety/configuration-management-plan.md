# Configuration Management Plan

**Project:** xdp-graph-lib
**Document ID:** XGL-CMP-001
**Version:** 1.0
**Date:** 2026-03-02
**Classification:** ISO 26262 Part 8, Clause 7
**Target ASIL:** ASIL-A
**Status:** Initial Release

---

## 1. Purpose

This document defines the configuration management practices for
xdp-graph-lib to ensure traceability, reproducibility, and controlled
change management as required by ISO 26262 Part 8, Clause 7.

---

## 2. Configuration Items

### 2.1 Source Code

| Category | Location | Files |
|---|---|---|
| Public headers | `include/xgl/` | 8 header files |
| BPF code | `src/bpf/` | 1 header, 1 source |
| Userspace library | `src/userspace/` | 4 source files |
| Unit tests | `tests/unit/` | 6 test files |
| Integration tests | `tests/integration/` | 2 test files |
| CBMC harnesses | `verification/cbmc/` | 2 harness files |
| TLA+ specs | `verification/tlaplus/` | 1 spec, 1 config |
| Examples | `examples/l2fwd/` | 3 source files |
| Build system | root | `meson.build`, `meson_options.txt` |

### 2.2 Safety Documentation

| Document | Location | Document ID |
|---|---|---|
| Software Safety Requirements | `docs/safety/software-safety-requirements.md` | XGL-SSRS-001 |
| Traceability Matrix | `docs/safety/traceability-matrix.md` | XGL-RTM-001 |
| FMEA | `docs/safety/fmea.md` | XGL-FMEA-001 |
| Architectural Design | `docs/safety/software-architectural-design.md` | XGL-SAD-001 |
| Tool Qualification | `docs/safety/tool-qualification.md` | XGL-TQR-001 |
| V&V Plan | `docs/safety/verification-validation-plan.md` | XGL-VVP-001 |
| CM Plan | `docs/safety/configuration-management-plan.md` | XGL-CMP-001 |

### 2.3 Tools and Dependencies

| Tool | Version | Purpose |
|---|---|---|
| GCC | 15.2.1 | C compiler |
| Clang | (system) | BPF compiler |
| Meson | 1.8.5 | Build system |
| libbpf | >= 1.0 | BPF library |
| libelf | 0.194 | ELF parsing |
| CBMC | 6.1.1 | Formal verification |
| TLC | tla2tools.jar | Model checking |
| gcovr | (system) | Coverage measurement |

---

## 3. Version Control

### 3.1 Repository

- **System:** Git
- **Host:** github.com/smgglrs/xdp-graph-lib
- **Branch model:** trunk-based development on `main`

### 3.2 Branching Strategy

| Branch | Purpose | Protection |
|---|---|---|
| `main` | Release-ready code | Protected: requires review |
| `feature/*` | Feature development | Merge via merge request |
| `fix/*` | Bug fixes | Merge via merge request |
| `release/v*` | Release branches | Tagged at release |

### 3.3 Commit Requirements

Every commit must:
1. Pass all automated tests (enforced by CI)
2. Include a descriptive message referencing the requirement or FMEA item
3. Not skip pre-commit hooks (`--no-verify` prohibited)

---

## 4. Change Control

### 4.1 Change Categories

| Category | Approval | Impact Assessment |
|---|---|---|
| Safety-critical (affects SSR) | Safety Engineer + Developer | RTM update, FMEA review, regression test |
| Non-safety (tests, docs, examples) | Developer | Regression test |
| Tool change (compiler, dependency version) | Safety Engineer | TQR update |

### 4.2 Change Process

1. Create merge request with description of change
2. Run full test suite (unit + integration + sanitizer)
3. Update affected safety documents (RTM, FMEA)
4. Independent review
5. Merge to `main`

---

## 5. Baseline Management

### 5.1 Release Baselines

Each release is tagged in Git with:
- Tag format: `v<major>.<minor>.<patch>`
- Annotated tag with release notes
- All safety documents at matching version

### 5.2 Current Baseline

| Item | Version |
|---|---|
| Source code | v0.1.0 (initial) |
| SSRS | 1.0 |
| RTM | 1.1 |
| FMEA | 1.0 |
| SAD | 1.0 |
| TQR | 1.0 |
| VVP | 1.0 |
| CMP | 1.0 |

---

## 6. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-02 | xdp-graph-lib team | Initial release |
