#include "vmlinux.h"
// #include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/pkt_cls.h>

#ifndef __inline
#define __inline inline __attribute__((always_inline))
#endif

#define ETH_HLEN 14 /* Total octets in header.	 */

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP                                                            \
  8 /* For hw path, this means "trap to cpu"                                   \
     * and don't further process the frame                                     \
     * in hardware. For sw path, this is                                       \
     * equivalent of TC_ACT_STOLEN - drop                                      \
     * the skb and act like everything                                         \
     * is alright.                                                             \
     */
#define TC_ACT_VALUE_MAX TC_ACT_TRAP

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
enum xdp_action {
  XDP_ABORTED = 0,
  XDP_DROP,
  XDP_PASS,
  XDP_TX,
  XDP_REDIRECT,
};

struct xdp_md {
  __u32 data;
  __u32 data_end;
  __u32 data_meta;
  /* Below access go through struct xdp_rxq_info */
  __u32 ingress_ifindex; /* rxq->dev->ifindex */
  __u32 rx_queue_index;  /* rxq->queue_index  */

  __u32 egress_ifindex; /* txq->dev->ifindex */
};

enum policy_action {
  ALLOW = 0,
  DENY,
  LOG,
};

struct netpolicy_rule {
  __u32 from[4];
  __u32 to[4];
  __u16 port;
  __u16 action;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct netpolicy_rule);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} netpolicy_rule SEC(".maps");

// ipv4 should be in big endian
static __inline struct netpolicy_rule *get_rule_from_ipv4(__u32 ipv4) {
  return bpf_map_lookup_elem(&netpolicy_rule, &ipv4);
}

static __inline int parse_l4(void *data, void *data_end, __u32 *src_addr,
                             __u32 *dest_addr, __u16 *src_port,
                             __u16 *dest_port) {
  // Then parse the IP header.
  struct iphdr *ip = (void *)(data + sizeof(struct ethhdr));
  if ((void *)(ip + 1) > data_end) {
    return 1;
  }
  *src_addr = ip->saddr;
  *dest_addr = ip->daddr;

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)((__u8 *)ip + ip->ihl);
    *dest_port = tcp->dest;
    *src_port = tcp->source;
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)((__u8 *)ip + ip->ihl);
    *dest_port = udp->dest;
    *src_port = udp->dest;
  } else {
    return 1;
  }
  return 0;
}

// enforce policy for traffic going into container
SEC("tc")
int wl_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  __u16 src_port, dest_port = 0;
  __u32 src_addr, dest_addr = 0;

  struct netpolicy_rule *rule = NULL;

  if (data_end < data + ETH_HLEN) {
    return TC_ACT_OK; // Not our packet, return it back to kernel
  }
  struct ethhdr *eth = data;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    return TC_ACT_OK;
  }

  int ret =
      parse_l4(data, data_end, &src_addr, &dest_addr, &src_port, &dest_port);
  if (ret == 0) {
    bpf_printk("tc egress protocol: %d, source: %u:%u, ", eth->h_proto,
               bpf_ntohl(src_addr), src_port);
    bpf_printk("dest: %u:%u\n", bpf_ntohl(dest_addr), dest_port);

    rule = get_rule_from_ipv4(dest_addr);
    if (rule) {
      if (rule->port == dest_port && rule->action == DENY) {
        bpf_printk("match rule, port %u, drop pkt\n", rule->port);
        return XDP_DROP;
      }
      return TC_ACT_SHOT;
    }
  }

  // Then parse the IP header.
  //   struct iphdr *ip = (void *)(eth + 1);
  //   if ((void *)(ip + 1) > data_end) {
  //     return TC_ACT_OK;
  //   }

  //   bpf_printk("tc egress protocol:  %d, source ip: %u, dest ip: %u\n",
  //              eth->h_proto, bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));

  //   rule = get_rule_from_ipv4(ip->saddr);
  //   if (rule) {
  //     bpf_printk("match rule, port %u, drop pkt\n", rule->port);
  //     return TC_ACT_SHOT;
  //   }

  return TC_ACT_OK;
}

// enforce policy for traffic coming from container
SEC("tc")
int wl_ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct netpolicy_rule *rule = NULL;

  if (data_end < data + ETH_HLEN) {
    return TC_ACT_OK; // Not our packet, return it back to kernel
  }
  struct ethhdr *eth = data;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    return TC_ACT_OK;
  }

  // Then parse the IP header.
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return TC_ACT_OK;
  }

  bpf_printk("tc ingress protocol:  %d, source ip: %u, dest ip: %u.\n",
             eth->h_proto, bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));

  rule = get_rule_from_ipv4(ip->saddr);
  if (rule) {
    bpf_printk("match rule, port %u, drop pkt\n", rule->port);
    return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

// enforce policy for traffic coming from container
SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct netpolicy_rule *rule = NULL;
  __u16 src_port, dest_port = 0;

  // First, parse the ethernet header.
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    return XDP_PASS;
  }

  // Then parse the IP header.
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  bpf_printk("xdp protocol:  %d, source ip: %u, dest ip: %u\n", eth->h_proto,
             bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr));

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)((char *)ip + ip->ihl);
    dest_port = tcp->dest;
    src_port = tcp->source;
  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)((char *)ip + ip->ihl);
    dest_port = udp->dest;
    src_port = udp->dest;
  } else {
    return XDP_PASS;
  }

  rule = get_rule_from_ipv4(ip->saddr);
  if (rule) {
    if (rule->port == dest_port && rule->action == DENY) {
      bpf_printk("match rule, port %u, drop pkt\n", rule->port);
      return XDP_DROP;
    }
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "GPL";