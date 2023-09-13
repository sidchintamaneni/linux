#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>

#define MAX_SSIZE 128 
SEC("tracepoint/syscalls/sys_enter_execve")
int testing_tailcall(void *ctx){
	
	
	bpf_printk("testing_tailcall function\n");
	
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} prog_array SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tailcall,
	},
};

static __attribute__((__noinline__)) int test_bpf2bpf_call(void *ctx){
	
	
	bpf_tail_call(ctx, &prog_array, 1);
	

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx){
	
	test_bpf2bpf_call(ctx);


	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
