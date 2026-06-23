APP := packet-drop-doctor
BINDIR := bin
BPF_PKG := ./internal/loader

.PHONY: all build generate generate-vmlinux test clean fmt vet run-trace run-top

all: generate build

generate-vmlinux:
	@./scripts/gen-vmlinux.sh

generate:
	go generate $(BPF_PKG)

build:
	mkdir -p $(BINDIR)
	go build -o $(BINDIR)/$(APP) ./cmd/packet-drop-doctor

test:
	go test ./...

fmt:
	gofmt -w ./cmd ./internal

vet:
	go vet ./...

run-trace: build
	sudo ./$(BINDIR)/$(APP) trace --duration 30s --explain

run-top: build
	sudo ./$(BINDIR)/$(APP) top --duration 30s

clean:
	rm -rf $(BINDIR)
	rm -f internal/loader/dropdoctor_bpf*.go internal/loader/dropdoctor_bpf*.o
