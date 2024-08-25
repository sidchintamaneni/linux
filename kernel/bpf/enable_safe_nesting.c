
#include <linux/bpf.h>
#include <linux/printk.h>

#define ARR_SIZE_10 10
#define ARR_SIZE_20 20

typedef struct test_stack_size  {
	char a;		// 1 byte -> add 7 bytes for the alignment
	double b;	// 8 byte
} tss;

// Stack depth consumed by bpf_nested_func2: 24
int noinline bpf_nested_func2(void) {

	pr_info("bpf_nested_func2: At the start\n");

	char stack[ARR_SIZE_20]; // 20 bytes

	int i = 0; // 4 bytes
	for(i = 0; i < ARR_SIZE_20; i++) {
		stack[i] = i;
	}

	for(i = 0; i < ARR_SIZE_20; i++) {
		pr_debug("bpf_nested_func2: printing to stack array"
			" values to avoid inlining: %d\n", stack[i]);
	}

	pr_info("bpf_nested_func2: The end\n");

	return 0;

}

// Stack depth consumed by bpf_nested_func1: 34
int noinline bpf_nested_func1(void) {

	pr_info("bpf_nested_func1: At the start\n");

	char stack[ARR_SIZE_10]; // 10 bytes
	tss tss1; // 16 bytes

	tss1.a = 'a';
	tss1.b = 10;

	int i = 0; // 4 bytes
	for(i = 0; i < ARR_SIZE_10; i++) {
		stack[i] = i;
	}

	for(i = 0; i < ARR_SIZE_10; i++) {
		pr_debug("bpf_nested_func1: printing to stack array"
			" values to avoid inlining: %d\n", stack[i]);
	}

	int ret = bpf_nested_func2(); // 4 bytes
	pr_info("bpf_nested_func1: after calling func2 ret value: %d\n", ret);
	pr_info("bpf_nested_func1: the end\n");

	return 0;

}
