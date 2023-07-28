#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_common.h"

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_enter_execve(void *ctx){

	
    bpf_printk("at the start");
    
    return 0;

}


SEC("tracepoint/syscalls/sys_exit_exit_group")
int trace_exit_execve(void *ctx){

	
    bpf_printk("at the end");
    
    return 0;

}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
