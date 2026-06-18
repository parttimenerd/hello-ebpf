#!/bin/bash
# Phase 3.3 scan: count bpf_probe_read_* call sites in bpf-samples that
# region inference would eliminate.
# Run from the repo root:  bash scripts/scan-probe-reads.sh

set -e
cd "$(dirname "$0")/.."

echo "=== bpf_probe_read_* usage in bpf-samples ==="
echo ""

SOURCES=$(find bpf-samples/src/main/java -name "*.java")

echo "USER reads (could be inferred from syscall arg provenance):"
grep -rn "bpf_probe_read_user" bpf-samples/src/main/java/ 2>/dev/null | grep -v "Binary" | sed 's|bpf-samples/src/main/java/||' | while read line; do echo "  $line"; done
USER_COUNT=$(grep -rn "bpf_probe_read_user" bpf-samples/src/main/java/ 2>/dev/null | grep -v "Binary" | wc -l | tr -d ' ')

echo ""
echo "KERNEL reads (could be inferred from kernel struct pointer provenance):"
grep -rn "bpf_probe_read_kernel\b" bpf-samples/src/main/java/ 2>/dev/null | grep -v "Binary" | sed 's|bpf-samples/src/main/java/||' | while read line; do echo "  $line"; done
KERNEL_COUNT=$(grep -rn "bpf_probe_read_kernel\b" bpf-samples/src/main/java/ 2>/dev/null | grep -v "Binary" | wc -l | tr -d ' ')

echo ""
echo "Summary: $USER_COUNT user reads, $KERNEL_COUNT kernel reads"
echo "Total boilerplate calls inference would eliminate: $((USER_COUNT + KERNEL_COUNT))"
