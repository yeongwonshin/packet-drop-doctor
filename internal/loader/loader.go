package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" dropdoctor ../../bpf/drop_doctor.bpf.c -- -I../../bpf -I/usr/include

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Runtime owns eBPF objects and links. The generated types are created by
// `go generate ./internal/loader`.
type Runtime struct {
	Objects dropdoctorObjects
	Link    link.Link
}

func New() (*Runtime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}

	var objs dropdoctorObjects
	if err := loadDropdoctorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "kfree_skb",
		Program: objs.HandleKfreeSkb,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach raw tracepoint kfree_skb: %w", err)
	}

	return &Runtime{Objects: objs, Link: lnk}, nil
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.Link != nil {
		_ = r.Link.Close()
	}
	return r.Objects.Close()
}
