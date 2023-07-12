#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/sock.h>
#include <net/net_namespace.h>


#define IF_NAME "eth0"
#define DIP     "172.21.223.192"
#define SIP     "192.168.111.2"
#define SPORT   31900
#define DPORT   31900

#define SRC_MAC {0xAA, 0xFC, 0x00, 0x00, 0x00, 0x01}
#define DST_MAC {0x08, 0x92, 0x04, 0xDE, 0xd7, 0x40}

struct socket *sock;

void sock_init(void)
{
    struct ifreq ifr;


    sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, 0, &sock);
    strcpy(ifr.ifr_name, IF_NAME);
    sock->ops->ioctl(sock, SIOCSIFNAME, (unsigned long)&ifr);
}

void build_cust_skb(void){

    struct net_device *netdev = NULL;
    struct net *net = NULL;
    struct sk_buff *skb = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct udphdr *udp_header = NULL;
    __be32 dip = in_aton(DIP);
    __be32 sip = in_aton(SIP);

    u8 buf[16] = {"hello world"};
    u16 data_len = sizeof(buf);

    u8 *pdata = NULL;
    u32 skb_len;
    u8 dst_mac[ETH_ALEN] = DST_MAC;
    u8 src_mac[ETH_ALEN] = SRC_MAC; 


    sock_init();
    net = sock_net((const struct sock *) sock->sk);
    netdev = dev_get_by_name(net, IF_NAME);
    skb_len = data_len 
        + sizeof(struct iphdr)
        + sizeof(struct udphdr) 
        + LL_RESERVED_SPACE(netdev);
    pr_info("iphdr	: %d\n", sizeof(struct iphdr));
    pr_info("udphdr	: %d\n", sizeof(struct udphdr));
    pr_info("data_len: %d\n", data_len);
    pr_info("skb_len	: %d\n", skb_len);
    
    skb = alloc_skb(skb_len, GFP_ATOMIC);
    if (!skb) {
        return;
    }

    skb_reserve(skb, LL_RESERVED_SPACE(netdev));
    skb->dev = netdev;
    skb->pkt_type = PACKET_OTHERHOST;
    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    skb->priority = 0;

    skb_set_network_header(skb, 0);
    skb_put(skb, sizeof(struct iphdr));


    skb_set_transport_header(skb, sizeof(struct iphdr));
    skb_put(skb, sizeof(struct udphdr));


    udp_header = udp_hdr(skb);
    udp_header->source = htons(SPORT);
    udp_header->dest = htons(DPORT);
    udp_header->check = 0;


    ip_header = ip_hdr(skb);
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_UDP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb->len);
    ip_header->check = 0;


    skb->csum = skb_checksum(skb, ip_header->ihl*4, skb->len-ip_header->ihl*4, 0);
    ip_header->check = ip_fast_csum(ip_header, ip_header->ihl);
    udp_header->check = csum_tcpudp_magic(sip, dip, skb->len-ip_header->ihl*4, IPPROTO_UDP, skb->csum);

    pdata = skb_put(skb, data_len);
    if (pdata) {
        memcpy(pdata, buf, data_len);
    }
    pr_info("payload:%20s\n", pdata);


    eth_header = (struct ethhdr *)skb_push(skb, ETH_HLEN);
    memcpy(eth_header->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth_header->h_source, src_mac, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP); 


    if (dev_queue_xmit(skb) < 0) {
        dev_put(netdev);
        kfree_skb(skb);
        pr_info("send packet by skb failed.\n");
        return;
    }
    pr_info("send packet by skb success.\n");

}
