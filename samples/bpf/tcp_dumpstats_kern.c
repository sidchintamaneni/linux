// SPDX-License-Identifier: GPL-2.0
/* Refer to samples/bpf/tcp_bpf.readme for the instructions on
 * how to run this sample program.
 */
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define INTERVAL			1000000000ULL

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";

struct {
	__uint(type,BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags,BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} bpf_next_dump SEC(".maps");

SEC("sockops")
int _sockops(struct bpf_sock_ops *ctx)
{
	bpf_printk("Starting here\n");
	struct bpf_tcp_sock *tcp_sk;
	struct bpf_sock *sk;
	__u64 *next_dump;
	__u64 now;

	u64 start_time, taken, total_time=0, best_time=1000,worst_time=0;
	for(int i=0;i<1024;i++){
		start_time = bpf_ktime_get_ns(); 
		bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_RTT_CB_FLAG);
		taken = bpf_ktime_get_ns() - start_time; 
		total_time += taken; 
		if(taken > worst_time)
			worst_time = taken;
		if(taken<best_time)
			best_time = taken;
	}
	bpf_printk("bpf_sock_ops_cb_flags_set Avg:%ld ns, Best:%ld ns, worst:%ld ns\n", total_time/1024, best_time, worst_time);
	sk = ctx->sk;
	if (!sk)
		return 1;

	total_time=0;best_time=1000;worst_time=0;	
	for(int i=0;i<1024;i++){
		start_time = bpf_ktime_get_ns(); 
		bpf_sk_storage_get(&bpf_next_dump, sk, NULL,BPF_SK_STORAGE_GET_F_CREATE);
		taken = bpf_ktime_get_ns() - start_time; 
		total_time += taken; 
		if(taken > worst_time)
			worst_time = taken;
		if(taken<best_time)
			best_time = taken;
	}
	bpf_printk("bpf_sk_storage_get Avg:%ld ns, Best:%ld ns, worst:%ld ns\n", total_time/1024, best_time, worst_time);
/*	if (!next_dump)
		return 1;

	now = bpf_ktime_get_ns();
	if (now < *next_dump)
		return 1;

	tcp_sk = bpf_tcp_sock(sk);
	if (!tcp_sk)
		return 1;

	*next_dump = now + INTERVAL;

	bpf_printk("dsack_dups=%u delivered=%u\n",
		   tcp_sk->dsack_dups, tcp_sk->delivered);
	bpf_printk("delivered_ce=%u icsk_retransmits=%u\n",
		   tcp_sk->delivered_ce, tcp_sk->icsk_retransmits);
*/
	return 1;
}
