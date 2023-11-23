package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/josharian/native"
	"golang.org/x/sys/unix"
)

const (
	QdiscKind = "clsact"

	TcaBpfFlagActDiretct = 1 << 0 // refer to include/uapi/linux/pkt_cls.h TCA_BPF_FLAG_ACT_DIRECT
	TcPrioFilter         = 1      // refer to include/uapi/linux/pkt_sched.h TC_PRIO_FILLER
)

var isBigEndian = native.IsBigEndian

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf  microseg_agent ./ebpf/net-policy.c

type PolicyEnforcer struct {
	object *microseg_agentObjects
}

func (p *PolicyEnforcer) initEbpfObjects() error {
	err := loadMicroseg_agentObjects(p.object, nil)
	if err != nil {
		fmt.Printf("load object %v\n", err)
		return err
	}
	return nil
}

func (p *PolicyEnforcer) attachTC(ifindex uint32, direction string, fd uint32, name string) error {
	config := &tc.Config{}
	rtnl, err := tc.Open(config)
	if err != nil {
		return err
	}
	defer func() {
		err = rtnl.Close()
		if err != nil {
			fmt.Printf("close rtnetlink %v\n", err)
		}
	}()

	qdiscInfo := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: QdiscKind,
		},
	}
	// create qdisc on interface if not exists
	if err := rtnl.Qdisc().Add(&qdiscInfo); err != nil && !errors.Is(err, os.ErrExist) {
		fmt.Printf("could not create %s qdisc to %d: %v\n", QdiscKind, ifindex, err)
		return err
	}

	flag := uint32(TcaBpfFlagActDiretct)
	filterEgress := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: ifindex,
			Handle:  1,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			// Info definition and usage could be referred from net/sched/cls_api.c 'tc_new_tfilter'
			// higher 16bits are used as priority, lower 16bits are used as protocol
			// refer include/net/sch_generic.h
			// prio is define as 'u32' while protocol is '__be16'. :(
			Info: core.BuildHandle(uint32(TcPrioFilter), uint32(htons(unix.ETH_P_ALL))),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Name:  &name,
				Flags: &flag,
			},
		},
	}
	err = rtnl.Filter().Replace(&filterEgress)
	if err != nil {
		fmt.Printf("replace tc filter %v", err)
		return err
	}

	return nil
}

func (p *PolicyEnforcer) updatePolicyRule() {

}

func main() {
	p := PolicyEnforcer{
		object: &microseg_agentObjects{},
	}
	err := p.initEbpfObjects()
	if err != nil {
		fmt.Printf("init ebpf object %v\n", err)
		return
	}
	_ = &tc.Config{}
	fd := p.object.microseg_agentPrograms.TcIngress.FD()
	info, err := p.object.microseg_agentPrograms.TcIngress.Info()
	if err != nil {
		fmt.Printf("get ingress %v", err)
		return
	}
	name := info.Name
	var ifindex uint32 = 4139

	err = p.attachTC(ifindex, "egress", uint32(fd), name)
	if err != nil {
		fmt.Printf("attatch tc %v", err)
		return
	}

}

func htons(a uint16) uint16 {
	if isBigEndian {
		return a
	}
	return (a&0xff)<<8 | (a&0xff00)>>8
}
