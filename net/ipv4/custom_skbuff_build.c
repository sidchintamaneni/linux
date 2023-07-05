#include<linux/netdevice.h>
#include<linux/skbuff.h>

#include<linux/printk.h>

//need to fake a skbuff and call dev_queue_xmit


void build_cust_skb(void){
    
    struct sk_buff *skb;
    struct net_device *dev;
    struct sock *sk;


    //alloc_skb
    skb = alloc_skb(0, GFP_KERNEL); 
    
    if(skb == NULL){
       pr_info("sk_buff allocation failed\n");
       return;
    } else {
        pr_info("sk_buff allocation successful\n");
    }
    

    out:
        kfree_skb(skb);

    

//    //reserving headspace
//    skb_reserve(skb, sizeof(ethhdr) + sizeof(iphdr) + size(icmphdr));
//
//    //putting userdata
//    unsigned char *data = skb_put(skb, /user_data_len/);
//    memcpy(data, 0x11, user_data_len);
//
//
//    //inserting headers
//    skb_push(skb, icmphdr);
//    skb_push(skb, iphdr);
//    skb_push(skb, ethhdr);
//
//
//    //inserting skb into the network
//    dev_queue_xmit(skb);

}
