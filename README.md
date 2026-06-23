# packet-drop-doctor

`packet-drop-doctor`는 Linux 네트워크 패킷이 **어디서, 왜 drop 되었는지**를 eBPF로 관찰하고 사람이 읽을 수 있는 설명으로 바꿔 주는 CLI입니다.

> 목표: “왜 통신이 안 되지?”라는 질문에 대해 `conntrack`, `firewall/netfilter`, `qdisc`, `routing`, `driver/NIC` 관점의 단서를 한 번에 보여 줍니다.

## 핵심 아이디어

Linux 커널의 `kfree_skb` drop 지점은 `skb_drop_reason`을 함께 전달합니다. 이 프로젝트는 raw tracepoint `kfree_skb`에 eBPF 프로그램을 붙여 drop 이벤트를 수집하고, 사용자 공간 CLI에서 다음 정보를 해석합니다.

- Drop reason code와 설명
- 인터페이스, 패킷 길이, L3/L4 프로토콜, IP/port 5-tuple
- `location` 심볼 주소를 이용한 커널 함수 힌트
- reason 기반 원인 분류: `conntrack`, `firewall`, `qdisc`, `routing`, `socket`, `driver`, `unknown`
- 실시간 trace 모드와 집계 top 모드

## 프로젝트 성숙도

이 레포는 바로 확장 가능한 **MVP 설계 + 구현 골격**입니다.

현재 포함된 것:

- eBPF CO-RE 프로그램: `bpf/drop_doctor.bpf.c`
- Go CLI skeleton: `cmd/packet-drop-doctor/main.go`
- reason 설명 엔진: `internal/doctor/explain.go`
- ringbuf 이벤트 구조체와 출력 renderer
- dev netns 기반 drop 재현 스크립트
- 설계 문서와 확장 로드맵

실서비스 수준으로 확장할 때 추가할 것:

- 커널 버전별 `skb_drop_reason` enum 자동 추출
- `nf_hook_slow`, `nft_do_chain`, `fib_table_lookup`, `sch_handle_egress` 등 보조 probe
- `location` 주소 → `/proc/kallsyms` symbolization
- Prometheus/OpenTelemetry export

## 요구 사항

- Linux kernel 5.17+ 권장, BTF 활성화 필요
- root 권한 또는 `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`
- Go 1.22+
- clang/llvm
- bpftool
- libbpf headers

Ubuntu 예시:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool libbpf-dev linux-tools-common make gcc
```

## 빠른 시작

```bash
make generate-vmlinux
make build
sudo ./bin/packet-drop-doctor trace --duration 30s --explain
```

드롭 상위 reason 보기:

```bash
sudo ./bin/packet-drop-doctor top --duration 60s
```

개발용 네임스페이스에서 일부 drop을 재현:

```bash
sudo ./scripts/dev-netns-demo.sh
sudo ./bin/packet-drop-doctor trace --duration 10s --explain
```

## CLI 예시

```text
$ sudo packet-drop-doctor trace --iface veth0 --duration 10s --explain
TIME       IFACE  FLOW                         REASON                 WHERE       WHY
12:01:33   veth0  10.10.0.2:41322 -> 8.8.8.8:53 UDP  NETFILTER_DROP   firewall    nftables/iptables 계층에서 DROP verdict 가능성이 큽니다.
12:01:34   eth0   10.0.0.5:0 -> 10.0.0.1:0 ICMP       NO_ROUTE        routing     FIB route lookup 실패 또는 정책 라우팅 누락 가능성이 큽니다.
```

## 디렉토리 구조

```text
packet-drop-doctor/
├── bpf/                         # eBPF 프로그램
├── cmd/packet-drop-doctor/       # CLI entrypoint
├── internal/doctor/              # event model, reason 설명, renderer
├── internal/loader/              # bpf2go loader 연결부
├── docs/                         # 설계/운영 문서
├── scripts/                      # 개발/재현 스크립트
└── testdata/                     # 샘플 이벤트
```

## 진단 모델

`packet-drop-doctor`는 단일 reason만 보여 주지 않고, 다음 방식으로 설명합니다.

1. **커널 drop reason**: `skb_drop_reason` raw value를 수집합니다.
2. **위치 힌트**: drop이 발생한 함수 주소 `location`을 함께 기록합니다.
3. **원인 도메인 분류**: reason과 위치를 `routing`, `firewall`, `conntrack`, `qdisc`, `driver`, `socket`으로 매핑합니다.
4. **사용자 액션 제안**: `ip route get`, `nft list ruleset`, `conntrack -S`, `tc -s qdisc` 등 다음 확인 명령을 제안합니다.

자세한 내용은 [`docs/design.md`](docs/design.md)를 참고하세요.

## 레포 이름 후보

- `packet-drop-doctor`
- `droptrace`
- `skb-doctor`
- `netdrop-explainer`
- `ebpf-drop-inspector`

## 라이선스

MIT
