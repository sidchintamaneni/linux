#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"

#define PIN_GLOBAL_NS		2
#define bpf_memcpy __builtin_memcpy
//check the macro definitions as well
#define ICMP_PING 8

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};


struct bpf_elf_map SEC("maps") icmp_ingress_data = {
    .type = BPF_MAP_TYPE_QUEUE,
    //	.size_key = sizeof(int),
    .size_value = sizeof(struct icmphdr),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 256,
};

//struct {
//    __uint(type, BPF_MAP_TYPE_HASH);
//    __type(key, int);
//    __type(value, struct icmphdr);
//    __uint(max_entries, 256);
//} icmp_data SEC(".maps");

SEC("ingress")
int identify_icmp_pkt(struct __sk_buff *skb){

    //    const int l3_off = ETH_HLEN;                      // IP header offset
    //    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset
    //
    //    void *data = (void*)(long)skb->data;
    //    void *data_end = (void*)(long)skb->data_end;
    //    if (data + l4_off > data_end)
    //        return TC_ACT_OK;
    //
    //    struct ethhdr *eth = data;
    //    if (eth->h_proto != htons(ETH_P_IP))
    //       return TC_ACT_OK;
    //
    //    struct iphdr *ip = (struct iphdr *)(data + l3_off);
    //    if (ip->protocol != IPPROTO_ICMP)
    //        return TC_ACT_OK;
    //    
    //    struct icmphdr *icmp = data + l4_off;
    //    int key = 0;
    //
    //    bpf_map_update_elem(&icmp_data, &key, icmp, BPF_ANY);
    //
    //    return TC_ACT_SHOT;

    bpf_printk("Inside the tcbpf1 kernel function\n");
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    void *ip_header = data + sizeof(struct ethhdr);
    if (ip_header + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    struct iphdr *ip = ip_header;
    if (ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    void *icmp_header = ip_header + sizeof(struct iphdr);
    if (icmp_header + sizeof(struct icmphdr) > data_end)
        return TC_ACT_OK;


    struct icmphdr *icmp = icmp_header;

    bpf_map_push_elem(&icmp_ingress_data, icmp, BPF_ANY);
    
    if(icmp->type != ICMP_PING)
        return TC_ACT_OK;
    //check the helper that we using below 
    __u8 src_mac[ETH_ALEN];
    __u8 dst_mac[ETH_ALEN];

    bpf_memcpy(src_mac, eth->h_source, ETH_ALEN);
    bpf_memcpy(dst_mac, eth->h_dest, ETH_ALEN);

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
    bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

    bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

    __u8 new_type = 0;
    bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, ICMP_PING, new_type, ICMP_CSUM_SIZE);
    bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

    bpf_clone_redirect(skb, skb->ifindex, 0);
    int key = 0;
    int val = 10;


    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
