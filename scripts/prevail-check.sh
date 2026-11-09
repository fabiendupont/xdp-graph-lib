#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# prevail-check.sh — bytecode-level verification gate.
#
# Runs the PREVAIL eBPF verifier (vbpf/prevail) on every BPF object
# under a build directory.  Deterministic and kernel-independent:
# the same object either verifies or it does not, on any machine,
# regardless of the host kernel version.
#
# Usage: prevail-check.sh <prevail-binary> <build-dir>
#
# Exits 0 if every program in every object verifies, 1 otherwise.
# Objects without BPF programs (no -l output) are skipped.

set -u

PREVAIL=${1:?usage: prevail-check.sh <prevail-binary> <build-dir>}
BUILDDIR=${2:?usage: prevail-check.sh <prevail-binary> <build-dir>}

fail=0
checked=0

for obj in $(find "$BUILDDIR" -name '*.bpf.o' -type f | sort); do
    # List programs: one "section=X function=Y" line per program.
    listing=$("$PREVAIL" -l "$obj" 2>/dev/null) || {
        echo "FAIL (parse): $obj"
        fail=1
        continue
    }

    [ -z "$listing" ] && continue

    while IFS= read -r line; do
        section=${line#section=}
        section=${section%% *}
        func=${line##* function=}

        checked=$((checked + 1))
        if "$PREVAIL" -q "$obj" "$section" "$func"; then
            echo "PASS: ${obj#$BUILDDIR/} $section/$func"
        else
            echo "FAIL: ${obj#$BUILDDIR/} $section/$func"
            "$PREVAIL" "$obj" "$section" "$func" || true
            fail=1
        fi
    done <<< "$listing"
done

echo "---"
echo "prevail: $checked program(s) checked, $([ $fail -eq 0 ] && echo all passed || echo FAILURES)"
exit $fail
