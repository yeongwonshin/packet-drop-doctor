# Demo scenario

## 1. 빌드

```bash
make generate-vmlinux
make build
```

## 2. Drop 유발

```bash
sudo ./scripts/dev-netns-demo.sh
```

## 3. Trace

```bash
sudo ./bin/packet-drop-doctor trace --duration 10s --explain
```

## 4. Top

```bash
sudo ./bin/packet-drop-doctor top --duration 10s
```

## 5. 수동 확인

```bash
sudo nft list ruleset
ip netns exec pdd-a ip route get 10.88.0.2
ip -s link
```
