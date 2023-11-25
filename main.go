package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/josharian/native"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	QdiscKind = "clsact"

	TcaBpfFlagActDiretct = 1 << 0 // refer to include/uapi/linux/pkt_cls.h TCA_BPF_FLAG_ACT_DIRECT
	TcPrioFilter         = 1      // refer to include/uapi/linux/pkt_sched.h TC_PRIO_FILLER

	MapsPinpath = "/sys/fs/bpf/microseg"

	ALLOW = 0
	DENY  = 1
	LOG   = 2
)

var isBigEndian = native.IsBigEndian

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -cflags "-D__TARGET_ARCH_x86" microseg_agent ./ebpf/net-policy.c

type NetpolicyRule struct {
	From   [16]byte
	To     [16]byte
	Port   uint16
	Action uint16
}

type PolicyEnforcer struct {
	object *microseg_agentObjects
}

func (p *PolicyEnforcer) initEbpfObjects() error {
	var options ebpf.CollectionOptions
	if _, err := os.Stat(MapsPinpath); err != nil {
		if os.IsNotExist(err) {
			if err := os.Mkdir(MapsPinpath, os.ModePerm); err != nil {
				return fmt.Errorf("unable to create ambient bpf mount directory: %v", err)
			}
		}
	}
	options.Maps.PinPath = MapsPinpath

	object := microseg_agentObjects{}
	err := loadMicroseg_agentObjects(&object, &options)
	if err != nil {
		fmt.Printf("load object: %v\n", err)
		return err
	}
	p.object = &object
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

func (p *PolicyEnforcer) attachXDP(iface *net.Interface) error {
	link, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return fmt.Errorf("getting interface %s by name: %w", iface.Name, err)
	}
	err = netlink.LinkSetXdpFdWithFlags(link, p.object.XdpIngress.FD(), nl.XDP_FLAGS_DRV_MODE)

	// _, err = link.AttachXDP(link.XDPOptions{
	// 	Program:   p.object.XdpIngress,
	// 	Interface: iface.Index,
	// })
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
		return err
	}
	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	return nil
}

func (p *PolicyEnforcer) updatePolicyRule() error {
	fromAddr, _ := netip.ParseAddr("172.17.0.1")
	from := fromAddr.As16()

	destAddr, _ := netip.ParseAddr("172.17.0.2")
	to := destAddr.As16()

	rule := NetpolicyRule{
		From:   from,
		To:     to,
		Port:   uint16(80),
		Action: DENY,
	}
	ip := destAddr.AsSlice()

	err := p.object.NetpolicyRule.Update(ip, rule, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		println("Please specify a network interface")
		return
	}
	ifaceName := os.Args[1]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// ifindex, err := strconv.ParseUint(os.Args[1], 10, 0)
	// if err != nil {
	// 	fmt.Printf("invalid if index %v", err)
	// 	return
	// }

	p := PolicyEnforcer{
		// object: &microseg_agentObjects{},
	}
	err = p.initEbpfObjects()
	if err != nil {
		fmt.Printf("init ebpf object: %v\n", err)
		return
	}

	// traffic going into container
	fd := p.object.WlEgress.FD()
	info, err := p.object.WlEgress.Info()
	if err != nil {
		fmt.Printf("get ingress %v", err)
		return
	}
	name := info.Name

	err = p.attachTC(uint32(iface.Index), "egress", uint32(fd), name)
	if err != nil {
		fmt.Printf("attach tc %v", err)
		return
	}

	// traffic coming from container
	err = p.attachXDP(iface)
	if err != nil {
		return
	}

	err = p.updatePolicyRule()
	if err != nil {
		fmt.Printf("update rule: %v", err)
		return
	}
}

func htons(a uint16) uint16 {
	if isBigEndian {
		return a
	}
	return (a&0xff)<<8 | (a&0xff00)>>8
}
