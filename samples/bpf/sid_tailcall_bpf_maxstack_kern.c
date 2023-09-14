#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_tracing.h>


#define HOOK_POINT SEC("kprobe/schedule")
#define SIZE_OF_STACK 208


static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls33(void *ctx){
    
    unsigned char stack_space[SIZE_OF_STACK] = {0};
    
    /* 8 byte */
    unsigned long int i = 0;
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    for(i = 0; i < SIZE_OF_STACK; i++) {
        stack_space[i] = i % 255;
    }   

    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    bpf_printk("Leaf Function :)\n");

    //bpf_tail_call(ctx, &prog_array_initX, 1);
    
    return 0;

}
HOOK_POINT
int testing_tail_func33(void *ctx){
	
    unsigned char stack_space[SIZE_OF_STACK] = {0};
    
    /* 8 byte */
    unsigned long int i = 0;
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    for(i = 0; i < SIZE_OF_STACK; i++) {
        stack_space[i] = i % 255;
    }   

    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    bpf_printk("Before calling 33 bpf-to-bpf call\n");

    testing_bpf_to_bpf_calls33(ctx); 
   
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init33 SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func33,
	},
};

#define RTAIL_CALL(X, Y) \
static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls ## X(void *ctx){ \
    unsigned char stack_space[SIZE_OF_STACK] = {0}; \
    unsigned long int i = 0; \
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);\
    for(i = 0; i < SIZE_OF_STACK; i++) {\
        stack_space[i] = i % 255;\
    }   \
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);\
    bpf_printk("Before calling %d tailcall\n", Y);\
    bpf_tail_call(ctx, &prog_array_init ## Y, 1); \
    return 0; \
} \
HOOK_POINT \
int testing_tail_func ## X(void *ctx){ \
    unsigned char stack_space[SIZE_OF_STACK] = {0}; \
    unsigned long int i = 0; \
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);\
    for(i = 0; i < SIZE_OF_STACK; i++) { \
        stack_space[i] = i % 255; \
    }   \
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);\
    bpf_printk("Before calling %d bpf-to-bpf call\n", X); \
    testing_bpf_to_bpf_calls ## X(ctx); \ 
    return 0; \
} \
struct { \
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY); \
	__uint(max_entries, 2); \
	__uint(key_size, sizeof(__u32)); \
	__array(values, int (void *)); \
} prog_array_init##X SEC(".maps") = { \
	.values = { \
		[1] = (void *)&testing_tail_func##X, \
	}, \
} \

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


static __attribute__((__noinline__)) int testing_bpf_to_bpf_calls(void *ctx){
    
    unsigned char stack_space[SIZE_OF_STACK] = {0};
    
    /* 8 byte */
    unsigned long int i = 0;
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    for(i = 0; i < SIZE_OF_STACK; i++) {
        stack_space[i] = i % 255;
    }   

    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    bpf_printk("Before calling 2 tailcall\n");

    bpf_tail_call(ctx, &prog_array_init2, 1);
    
    return 0;

}


HOOK_POINT
int testing_tail_func(void *ctx){
	
    unsigned char stack_space[SIZE_OF_STACK] = {0};
    
    /* 8 byte */
    unsigned long int i = 0;
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    for(i = 0; i < SIZE_OF_STACK; i++) {
        stack_space[i] = i % 255;
    }   

    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    bpf_printk("Before calling 1 bpf-to-bpf call\n");

    testing_bpf_to_bpf_calls(ctx); 
   
    return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 10);
	__uint(key_size, sizeof(__u32));
	__array(values, int (void *));
} prog_array_init SEC(".maps") = {
	.values = {
		[1] = (void *)&testing_tail_func,
	},
};


HOOK_POINT
int bpf_max_stack_enter(void *ctx){
    bpf_printk("bpf_max_stack_enter: at the start\n");
    
    unsigned char stack_space[SIZE_OF_STACK] = {0};
    /* 8 byte */
    unsigned long int i = 0;
    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    for(i = 0; i < SIZE_OF_STACK; i++) {
        stack_space[i] = i % 255;
    }   

    bpf_printk("value of i: %d, address of stack_space[i]: %llu\n", i,(unsigned long long) &stack_space[i]);

    bpf_printk("Before calling 1 tailcall\n");

    bpf_tail_call(ctx, &prog_array_init, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
