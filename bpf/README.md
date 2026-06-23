# bpf/

이 디렉토리는 커널 공간에서 실행되는 eBPF 프로그램을 담습니다.

## 파일

- `drop_doctor.bpf.c`: `raw_tracepoint/kfree_skb`에 attach되는 MVP 프로그램
- `vmlinux.h`: 로컬 커널 BTF에서 생성되는 CO-RE header. git에는 포함하지 않습니다.

## 생성

```bash
make generate-vmlinux
```

## 개발 원칙

- tracepoint/fentry 우선, kprobe는 fallback으로 사용합니다.
- 커널 구조체 접근은 `BPF_CORE_READ`로 수행합니다.
- ringbuf event 구조체 변경 시 Go `doctor.Event`와 layout을 맞춰야 합니다.
