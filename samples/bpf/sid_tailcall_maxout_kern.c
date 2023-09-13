#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>


SEC("fentry/__x64_sys_execve")
int testing_func34(void *ctx){
    bpf_printk("inside tail-call 34");
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init34 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_func34,
	},
};
SEC("fentry/__x64_sys_execve")
int testing_func33(void *ctx){
    bpf_printk("inside tail-call 33");
    bpf_tail_call(ctx, &prog_array_init34, 1);
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init33 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_func33,
	},
};

#define RTAIL_CALL(X, Y) \
SEC("fentry/__x64_sys_execve") \
int testing_func ## X(void *ctx){ \
    bpf_printk("inside tail-call %s",#X); \
    bpf_tail_call(ctx, &prog_array_init##Y, 1); \
    return 0; \
} \
struct { \
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \
	__uint(max_entries, 2); \
	__uint(key_size, sizeof(__u32)); \
	__array(values, int (void *)); \
} prog_array_init##X SEC(".maps") = { \
	.values = { \
		[1] = (void *)&testing_func##X, \
	}, \
} \

//RTAIL_CALL(40, 41);
//RTAIL_CALL(39, 40);
//RTAIL_CALL(38, 39);
//RTAIL_CALL(37, 38);
//RTAIL_CALL(36, 37);
//RTAIL_CALL(35, 36);
//RTAIL_CALL(34, 35);
//RTAIL_CALL(33, 34);
RTAIL_CALL(32, 33);
RTAIL_CALL(31, 32);
RTAIL_CALL(30, 31);
RTAIL_CALL(29, 30);
RTAIL_CALL(28, 29);
RTAIL_CALL(27, 28);
RTAIL_CALL(26, 27);
RTAIL_CALL(25, 26);
RTAIL_CALL(24, 25);
RTAIL_CALL(23, 24);
RTAIL_CALL(22, 23);
RTAIL_CALL(21, 22);
RTAIL_CALL(20, 21);
RTAIL_CALL(19, 20);
RTAIL_CALL(18, 19);
RTAIL_CALL(17, 18);
RTAIL_CALL(16, 17);
RTAIL_CALL(15, 16);
RTAIL_CALL(14, 15);
RTAIL_CALL(13, 14);
RTAIL_CALL(12, 13);
RTAIL_CALL(11, 12);
RTAIL_CALL(10, 11);
RTAIL_CALL(9, 10);
RTAIL_CALL(8, 9);
RTAIL_CALL(7, 8);
RTAIL_CALL(6, 7);
RTAIL_CALL(5, 6);
RTAIL_CALL(4, 5);
RTAIL_CALL(3, 4);
RTAIL_CALL(2, 3);


SEC("fentry/__x64_sys_execve")
int testing_func(void *ctx){
    bpf_printk("inside tail-call 1");

    bpf_tail_call(ctx, &prog_array_init2, 1);
    return 0;
}


struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
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
