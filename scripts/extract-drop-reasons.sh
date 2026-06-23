#!/usr/bin/env bash
set -euo pipefail

# Best-effort helper to inspect the target kernel's skb_drop_reason enum.
# Numeric values can change across kernel versions, so production builds should
# generate a version-specific map instead of hard-coding every reason.

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool is required." >&2
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c \
  | awk '/enum skb_drop_reason/,/};/'
