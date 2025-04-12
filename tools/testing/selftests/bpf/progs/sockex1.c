// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) XXXXXXX */
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


__u64 invocation_icmp = 0;

SEC("sockex1")
int bpf_prog1(struct __sk_buff *skb)
{
	bpf_printk("BPF program triggered\n");

	__sync_fetch_and_add(&invocation_icmp, 1);

	bpf_printk("BPF program triggered: %d\n", invocation_icmp);

	return 0;
}

char _license[] SEC("license") = "GPL";
