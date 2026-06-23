#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT_DIR}/bpf/vmlinux.h"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "BTF file /sys/kernel/btf/vmlinux not found. Enable CONFIG_DEBUG_INFO_BTF or install a kernel with BTF." >&2
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool is required." >&2
  exit 1
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${OUT}"
echo "generated ${OUT}"
