// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// packet-drop-doctor eBPF program
//
// MVP hook: raw_tracepoint/kfree_skb
// The raw tracepoint receives the original tracepoint arguments without a
// generated trace_event struct. This makes the program less sensitive to minor
// tracepoint format differences between kernels.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define MAX_EVENTS 16384

struct drop_key {
    __u32 reason;
    __u32 ifindex;
    __u8 l4_proto;
    __u8 _pad[3];
};

struct drop_value {
    __u64 packets;
    __u64 bytes;
};

struct drop_event {
    __u64 ts_ns;
    __u64 location;
    __u32 reason;
    __u32 ifindex;
    __u32 len;
    __u32 mark;
    __u32 pid;
    __u16 protocol;
    __u8 l4_proto;
    __u8 ip_version;
    __u32 saddr_v4;
    __u32 daddr_v4;
    __u16 sport;
    __u16 dport;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_EVENTS * sizeof(struct drop_event));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct drop_key);
    __type(value, struct drop_value);
} stats SEC(".maps");

static __always_inline void count_drop(struct drop_event *e) {
    struct drop_key key = {};
    struct drop_value init = {};
    struct drop_value *value;

    key.reason = e->reason;
    key.ifindex = e->ifindex;
    key.l4_proto = e->l4_proto;

    value = bpf_map_lookup_elem(&stats, &key);
    if (!value) {
        init.packets = 1;
        init.bytes = e->len;
        bpf_map_update_elem(&stats, &key, &init, BPF_ANY);
        return;
    }

    __sync_fetch_and_add(&value->packets, 1);
    __sync_fetch_and_add(&value->bytes, e->len);
}

static __always_inline void read_l4_ports(void *head, __u16 transport_header, __u8 proto, struct drop_event *e) {
    if (transport_header == 0) {
        return;
    }

    if (proto == IPPROTO_TCP) {
        struct tcphdr tcp = {};
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) == 0) {
            e->sport = bpf_ntohs(tcp.source);
            e->dport = bpf_ntohs(tcp.dest);
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr udp = {};
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
            e->sport = bpf_ntohs(udp.source);
            e->dport = bpf_ntohs(udp.dest);
        }
    }
}

static __always_inline void parse_ipv4(struct sk_buff *skb, struct drop_event *e) {
    void *head = NULL;
    __u16 network_header = 0;
    __u16 transport_header = 0;
    struct iphdr iph = {};

    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);
    transport_header = BPF_CORE_READ(skb, transport_header);

    if (!head || network_header == 0) {
        return;
    }

    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) {
        return;
    }

    if (iph.version != 4) {
        return;
    }

    e->ip_version = 4;
    e->l4_proto = iph.protocol;
    e->saddr_v4 = iph.saddr;
    e->daddr_v4 = iph.daddr;

    read_l4_ports(head, transport_header, iph.protocol, e);
}

SEC("raw_tracepoint/kfree_skb")
int handle_kfree_skb(struct bpf_raw_tracepoint_args *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    void *location = (void *)ctx->args[1];
    __u32 reason = (__u32)ctx->args[2];
    struct net_device *dev = NULL;
    struct drop_event *e;
    __u16 proto = 0;

    if (!skb) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->location = (__u64)location;
    e->reason = reason;
    e->len = BPF_CORE_READ(skb, len);
    e->mark = BPF_CORE_READ(skb, mark);
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        e->ifindex = BPF_CORE_READ(dev, ifindex);
    }

    proto = BPF_CORE_READ(skb, protocol);
    e->protocol = bpf_ntohs(proto);

    if (proto == bpf_htons(ETH_P_IP)) {
        parse_ipv4(skb, e);
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        e->ip_version = 6;
        // IPv6 parser intentionally left as a roadmap item. The CLI still
        // reports reason, interface and location for IPv6 drops.
    }

    count_drop(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
