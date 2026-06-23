# Design: eBPF 기반 Packet Drop Reason Analyzer

## 1. 문제 정의

운영 환경에서 “통신이 안 된다”는 증상은 여러 계층에서 발생할 수 있습니다.

- 라우팅 실패: route 없음, policy routing 누락, rp_filter
- 방화벽: nftables/iptables DROP verdict
- conntrack: table full, invalid state, NAT state mismatch
- qdisc/tc: queue overflow, shaping, tc filter drop
- socket: receive buffer 부족, checksum 문제, TCP state 문제
- device/driver: MTU, NIC queue, XDP drop

기존 도구는 각 계층을 따로 확인해야 합니다.

```bash
ip route get ...
nft list ruleset
conntrack -S
tc -s qdisc show dev eth0
ethtool -S eth0
ss -s
```

`packet-drop-doctor`는 커널 drop 이벤트를 중심으로 이 단서를 묶어서 설명합니다.

## 2. MVP 범위

MVP는 `raw_tracepoint/kfree_skb` 하나로 시작합니다.

수집 필드:

- timestamp
- skb_drop_reason numeric code
- drop location pointer
- ifindex
- skb length, mark
- L2 protocol
- IPv4 src/dst
- TCP/UDP src/dst port
- current process name

사용자 공간에서 수행:

- reason code → reason name heuristic mapping
- reason name → domain mapping
- domain → suggested checks
- 실시간 trace 출력
- reason/interface/protocol 집계

## 3. 왜 kfree_skb인가?

많은 네트워크 drop 경로는 최종적으로 `kfree_skb_reason()` 또는 관련 경로를 통해 skb를 해제합니다. 커널 tracepoint는 drop reason을 함께 노출하므로, 네트워크 스택 전체의 “최종 drop 이벤트”를 관찰하는 진입점으로 적합합니다.

단점도 있습니다.

- 모든 drop이 같은 수준의 세부 정보를 제공하지 않습니다.
- reason numeric value는 커널 버전에 따라 달라질 수 있습니다.
- `location`은 주소이므로 심볼화가 필요합니다.
- netfilter chain/rule 번호, qdisc classid 같은 세부 원인은 추가 probe가 필요합니다.

## 4. 아키텍처

```text
        kernel space                                  user space
┌────────────────────────┐                    ┌─────────────────────────┐
│ raw_tp/kfree_skb       │                    │ packet-drop-doctor CLI  │
│  - reason              │ ringbuf            │  trace/top/explain      │
│  - location            ├───────────────────▶│                         │
│  - skb metadata        │                    │ reason classifier       │
│  - 5-tuple parser      │ stats map          │ renderer/json           │
└────────────────────────┘                    └─────────────────────────┘
          │                                               │
          │ future probes                                 │ suggested checks
          ▼                                               ▼
┌────────────────────────┐                    ┌─────────────────────────┐
│ nf_hook_slow/nft chain │                    │ nft, conntrack, tc, ip  │
│ fib lookup             │                    │ ethtool, ss             │
│ tc/qdisc enqueue/drop  │                    └─────────────────────────┘
└────────────────────────┘
```

## 5. 원인 분류 모델

분류는 “단정”이 아니라 “우선 확인해야 할 계층”을 알려 주는 방식입니다.

| Domain | Trigger 예시 | 다음 확인 |
|---|---|---|
| firewall | `NETFILTER_DROP`, `NF_*` | `nft list ruleset`, `iptables-save` |
| conntrack | `CONNTRACK`, `CT_*` | `conntrack -S`, `nf_conntrack_count` |
| routing | `NO_ROUTE`, `RPFILTER`, `IP_*`, `XFRM` | `ip route get`, `ip rule show`, `rp_filter` |
| qdisc | `QDISC`, `TC_*`, queue 관련 | `tc -s qdisc`, `tc -s filter` |
| socket | `NO_SOCKET`, `SOCKET_*`, `TCP_*`, `UDP_*` | `ss -s`, `netstat -s` |
| driver | `DEV_*`, `DRIVER`, `XDP` | `ip -s link`, `ethtool -S` |

## 6. 확장 설계

### 6.1 Firewall deep reason

추가 probe 후보:

- `fentry/nf_hook_slow`
- `kprobe/nft_do_chain`
- `tracepoint/nf/nf_hook_slow`가 있는 커널에서는 tracepoint 우선

수집 목표:

- hook: prerouting/input/forward/output/postrouting
- pf: IPv4/IPv6/bridge
- verdict: drop/accept/stolen/queue
- chain/table/rule handle 힌트

출력 예:

```text
WHY: nftables input chain rule handle 42 returned DROP
CHECK: sudo nft -a list chain inet filter input
```

### 6.2 Conntrack deep reason

추가 probe 후보:

- `kprobe/nf_conntrack_in`
- `kprobe/nf_conntrack_tuple_taken`
- `tracepoint/nf_conntrack/nf_conntrack_*` 사용 가능 시 우선

수집 목표:

- invalid state
- table full
- NAT tuple collision
- expectation mismatch

출력 예:

```text
WHY: conntrack table is near capacity; new flows may be dropped or marked invalid
CHECK: sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
```

### 6.3 Qdisc/tc deep reason

추가 probe 후보:

- `fentry/sch_handle_egress`
- `kprobe/qdisc_drop`
- `kprobe/tcf_classify`

수집 목표:

- ingress/egress 방향
- qdisc 종류
- classid
- tc action drop 여부

출력 예:

```text
WHY: tc egress filter returned shot/drop action
CHECK: tc -s filter show dev eth0 egress
```

### 6.4 Routing deep reason

추가 probe 후보:

- `kprobe/fib_table_lookup`
- `kprobe/ip_route_input_noref`
- `kprobe/ip6_route_input_lookup`

수집 목표:

- no route
- blackhole/prohibit/unreachable route
- policy rule mismatch
- rp_filter

출력 예:

```text
WHY: FIB lookup returned unreachable route
CHECK: ip route get 10.0.2.15 from 10.0.1.10 iif eth0
```

## 7. 운영 고려사항

### 성능

- ringbuf 이벤트는 샘플링 옵션을 추가할 수 있습니다.
- 고트래픽 환경에서는 aggregation map만 켜고 trace 출력은 제한해야 합니다.
- per-CPU map 또는 LRU hash map으로 lock contention을 줄입니다.

### 안정성

- CO-RE 기반으로 커널 구조체 offset 변화에 대응합니다.
- reason numeric mapping은 target kernel BTF에서 생성하는 방식을 권장합니다.
- 보조 probe는 커널 심볼 존재 여부를 탐지한 뒤 가능한 것만 attach합니다.

### 권한

최소 권한 운영을 위해 다음 capability 조합을 검토합니다.

- `CAP_BPF`
- `CAP_PERFMON`
- `CAP_NET_ADMIN`
- 일부 배포판/커널에서는 root 필요

## 8. 로드맵

### v0.1

- `kfree_skb` event trace
- IPv4 5-tuple parser
- top aggregation
- built-in explanation map

### v0.2

- `/proc/kallsyms` location symbolization
- kernel BTF 기반 `skb_drop_reason` enum 추출
- JSON output 안정화

### v0.3

- netfilter/nftables deep probe
- conntrack table 상태 correlation
- tc/qdisc probe

### v0.4

- Prometheus exporter
- OpenTelemetry event export
- TUI dashboard

## 9. 한 줄 포지셔닝

> `packet-drop-doctor`는 tcpdump가 “패킷이 보이는지”를 알려 준다면, “보였던 패킷이 왜 사라졌는지”를 설명하는 도구입니다.
