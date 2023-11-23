package main

import (
	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf  microseg_agent ./ebpf/net-policy.c

func attachFilter(attachTo string, program *ebpf.Program) error {
	return nil
}
func main() {
	_ = &tc.Config{}
}
