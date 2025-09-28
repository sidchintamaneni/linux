#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/syscalls.h>

static noinline void dummy_trace_call(struct pt_regs *regs) {
	return;
}

SYSCALL_DEFINE0(bpfprof)
{
	dummy_trace_call(NULL);
	return 0;
}
