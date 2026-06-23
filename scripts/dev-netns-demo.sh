#!/usr/bin/env bash
set -euo pipefail

# Creates two namespaces and intentionally blocks ICMP/UDP traffic with nftables
# so packet-drop-doctor can observe NETFILTER-like drops.
# Cleanup: sudo ip netns del pdd-a; sudo ip netns del pdd-b; sudo nft delete table inet pdd_demo

NS_A="pdd-a"
NS_B="pdd-b"
VETH_A="veth-pdd-a"
VETH_B="veth-pdd-b"

cleanup() {
  ip netns del "${NS_A}" 2>/dev/null || true
  ip netns del "${NS_B}" 2>/dev/null || true
  nft delete table inet pdd_demo 2>/dev/null || true
}

cleanup
ip netns add "${NS_A}"
ip netns add "${NS_B}"
ip link add "${VETH_A}" type veth peer name "${VETH_B}"
ip link set "${VETH_A}" netns "${NS_A}"
ip link set "${VETH_B}" netns "${NS_B}"

ip -n "${NS_A}" addr add 10.88.0.1/24 dev "${VETH_A}"
ip -n "${NS_B}" addr add 10.88.0.2/24 dev "${VETH_B}"
ip -n "${NS_A}" link set lo up
ip -n "${NS_B}" link set lo up
ip -n "${NS_A}" link set "${VETH_A}" up
ip -n "${NS_B}" link set "${VETH_B}" up

nft add table inet pdd_demo
nft 'add chain inet pdd_demo input { type filter hook input priority 0; policy accept; }'
nft add rule inet pdd_demo input ip saddr 10.88.0.1 ip daddr 10.88.0.2 drop

set +e
ip netns exec "${NS_A}" ping -c 2 -W 1 10.88.0.2 >/dev/null
set -e

echo "Demo namespaces created. Try:"
echo "  sudo ./bin/packet-drop-doctor trace --duration 10s --explain"
echo "Cleanup:"
echo "  sudo ip netns del ${NS_A}; sudo ip netns del ${NS_B}; sudo nft delete table inet pdd_demo"
