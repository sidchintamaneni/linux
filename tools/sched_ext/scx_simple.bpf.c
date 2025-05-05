/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	bpf_printk("simple_select_cpu: triggered for task %d and task is triggered on"
			" cpu %d\n", 
			p->tgid, bpf_get_smp_processor_id());
	bpf_printk("simple_select_cpu: triggered for task %d and prev_cpu %d\n", 
			p->tgid, prev_cpu);
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	bpf_printk("simple_enqueue: triggered for task %d and task is triggered on"
			" cpu %d\n", 
			p->tgid, bpf_get_smp_processor_id());
	bpf_printk("simple_enqueue: triggered for task %d and FIFO %d\n", 
			p->tgid, fifo_sched);
	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		// updated vtime
		u64 vtime = p->scx.dsq_vtime;
		bpf_printk("simple_enqueue: (bef)triggered for task %d and vtime %ld\n", 
				p->tgid, vtime);

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		
		bpf_printk("simple_enqueue: (aft)triggered for task %d and vtime %ld\n", 
				p->tgid, vtime);

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	if (!prev)
		return;
	bpf_printk("simple_dispatch: triggered for task %d and task is triggered on"
			" cpu %d\n", 
			bpf_get_current_pid_tgid()>>32, bpf_get_smp_processor_id());
	bpf_printk("simple_dispatch: triggered for prev task %d and prev cpu %d\n", 
			BPF_CORE_READ(prev, tgid), cpu);
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	bpf_printk("simple_running: triggered for task %d and FIFO %d\n", 
			p->tgid, fifo_sched);
	bpf_printk("simple_running: triggered for task %d and task is triggered on"
			" cpu %d\n", 
			p->tgid, bpf_get_smp_processor_id());
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	// Updated the vtime_time
	// if vtime_now < p->scx.dsq_vtime
	bpf_printk("simple_running: (before)triggered for task %d, vtime_now %ld"
			" and p->scx.dsq_vtime %ld\n", 
			p->tgid, vtime_now, p->scx.dsq_vtime);
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
	bpf_printk("simple_running: (after)triggered for task %d, vtime_now %ld"
			" and p->scx.dsq_vtime %ld\n", 
			p->tgid, vtime_now, p->scx.dsq_vtime);

}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	bpf_printk("simple_stopping: triggered for task %d and FIFO %d\n", 
			p->tgid, fifo_sched);
	bpf_printk("simple_stopping: triggered for task %d and task is triggered on"
			" cpu %d\n", 
			p->tgid, bpf_get_smp_processor_id());
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	bpf_printk("simple_stopping: triggered for task %d and p->scx.dsq_vtime %ld"
			" p->scx.slice %ld and p->scx.weight %d\n", 
			p->tgid, p->scx.dsq_vtime, p->scx.slice, p->scx.weight);
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
	bpf_printk("simple_stopping: triggered for task %d and p->scx.dsq_vtime %ld\n", 
			p->tgid, p->scx.dsq_vtime);
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	bpf_printk("simple_enable: triggered for task %d and vtime_now %ld\n", 
			p->tgid, vtime_now);
	// vtime_now is some kinda global variable
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	bpf_printk("simple_init: Initialized the BPF schedular\n");
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	bpf_printk("simple_exit: Exited the BPF schedular\n");
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
	       .dispatch		= (void *)simple_dispatch,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
	       .enable			= (void *)simple_enable,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "simple");
