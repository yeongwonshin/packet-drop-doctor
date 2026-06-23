# Contributing

## 개발 환경

```bash
sudo apt-get install -y clang llvm bpftool libbpf-dev make gcc
make generate-vmlinux
make generate
make test
```

## PR 체크리스트

- [ ] eBPF event 구조체 변경 시 Go mirror struct 업데이트
- [ ] kernel version dependency 문서화
- [ ] reason/domain 설명 추가 시 test 추가
- [ ] root 권한이 필요한 테스트와 pure Go 테스트 분리

## 커밋 범위 예시

- `bpf:` eBPF 프로그램 변경
- `cli:` CLI UX 변경
- `doctor:` reason explanation 변경
- `docs:` 문서 변경
