# Drop reason map strategy

`skb_drop_reason`은 Linux 커널 enum입니다. enum 항목은 커널 버전에 따라 추가될 수 있으므로, 프로덕션 도구는 숫자 값을 고정해서 믿지 않는 편이 안전합니다.

## 권장 전략

1. 개발 편의용 built-in heuristic map을 둡니다.
2. 실행 호스트의 BTF에서 `enum skb_drop_reason`을 추출합니다.
3. 추출된 enum map을 캐시합니다.
4. 숫자 reason을 target kernel 기준 symbol로 변환합니다.

## 수동 확인

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c \
  | awk '/enum skb_drop_reason/,/};/'
```

또는 포함된 스크립트:

```bash
./scripts/extract-drop-reasons.sh
```

## 향후 구현 제안

Go에서 다음 방식으로 자동화할 수 있습니다.

- `bpftool btf dump` 실행 결과를 parse
- `enum skb_drop_reason` block 추출
- `SKB_DROP_REASON_` prefix 제거
- JSON cache 저장: `/var/cache/packet-drop-doctor/drop-reasons-$(uname -r).json`

예시 캐시 형식:

```json
{
  "kernel": "6.8.0-xx-generic",
  "enum": "skb_drop_reason",
  "values": {
    "7": "NETFILTER_DROP"
  }
}
```

## 주의

- 커널 config, vendor patch, backport에 따라 값이 다를 수 있습니다.
- 컨테이너 내부에서 실행할 경우 host `/sys/kernel/btf/vmlinux`를 읽어야 합니다.
- kallsyms symbolization도 host namespace 기준으로 해야 합니다.
