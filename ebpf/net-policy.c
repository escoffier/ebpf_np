#include "vmlinux.h"
// #include <linux/if_ether.h>
// #include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __inline
#define __inline                         \
   inline __attribute__((always_inline))
#endif

#define ETH_HLEN	14		/* Total octets in header.	 */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/


#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8 /* For hw path, this means "trap to cpu"
				   * and don't further process the frame
				   * in hardware. For sw path, this is
				   * equivalent of TC_ACT_STOLEN - drop
				   * the skb and act like everything
				   * is alright.
				   */
#define TC_ACT_VALUE_MAX	TC_ACT_TRAP

struct netpolicy_rule {
    __u32 address[2];
    __u16 ports;
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct netpolicy_rule);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_map SEC(".maps");

static __inline struct app_info * get_app_info_from_ipv4(__u32 ipv4)
{
    return bpf_map_lookup_elem(&rule_map, &ipv4);
}

SEC("tc") 
int wl_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

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

  bpf_printk("tc egress protocol:  %d, source ip: %u, dest ip: %d.\n",
             eth->h_proto, ip->saddr, ip->daddr);
  return TC_ACT_OK;
}