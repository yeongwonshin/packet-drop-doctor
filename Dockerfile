FROM golang:1.23-bookworm AS dev

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm bpftool libbpf-dev make gcc iproute2 nftables ethtool conntrack \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY . .

# The final build still needs the host kernel's /sys/kernel/btf/vmlinux mounted
# or bpf/vmlinux.h generated on the host.
CMD ["bash"]
