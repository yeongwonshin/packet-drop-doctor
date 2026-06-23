# CLI specification

## `trace`

실시간 drop event를 출력합니다.

```bash
packet-drop-doctor trace [--duration 30s] [--iface eth0] [--json] [--explain]
```

출력 컬럼:

- `TIME`: 이벤트 시각
- `IFACE`: skb가 연결된 net_device
- `FLOW`: IPv4 5-tuple
- `REASON`: drop reason symbol 또는 fallback
- `WHERE`: 분류된 원인 계층
- `WHY`: 사람이 읽는 설명

## `top`

지정한 시간 동안 drop을 집계합니다.

```bash
packet-drop-doctor top --duration 60s --iface eth0
```

집계 기준:

- reason
- ifindex
- L4 protocol

## `explain`

reason 숫자를 내장 heuristic map으로 설명합니다.

```bash
packet-drop-doctor explain 7
```

주의: reason 숫자는 커널 버전에 따라 다를 수 있습니다. 운영에서는 BTF 기반 reason map 생성을 권장합니다.
