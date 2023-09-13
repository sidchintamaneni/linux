#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>



SEC("fentry/__x64_sys_execve")
int testing_func_user(void *ctx){
    bpf_printk("inside testing_func_user");

    return 0;
}

SEC("fentry/__x64_sys_execve")
int testing_func(void *ctx){
    bpf_printk("inside testing_func");

    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_func,
	},
};

SEC("fentry/__x64_sys_execve")
int trace_enter_execve(struct pt_regs *ctx)
{	
    bpf_printk("Inside Kernel Main Function");

    bpf_tail_call(ctx, &prog_array_init, 1);

    return 0;	
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
