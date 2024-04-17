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
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool switch_partial;

UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define NSEC_PER_MSEC ((u64)1e6)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */ // cambio questo per array più lungo
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}


static u64 get_time_slice(struct task_struct *task){
	int msecs = task->prio - 100;
	// priority in standard goes from 100 and 139
	// so now time go 0 and 39
	msecs = 40 - msecs;
	// reversing because lower priority = more time for now
	// it goes from 40 to 1
	if(msecs == 40)
		msecs = 20;
	else
		msecs = 10;
	// square last result
	return msecs * NSEC_PER_MSEC;
}

s32 BPF_STRUCT_OPS(simple_mine_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, get_time_slice(p), 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_mine_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing -> data printed */

	scx_bpf_dispatch(p, SHARED_DSQ, get_time_slice(p), enq_flags);
}

void BPF_STRUCT_OPS(simple_mine_dispatch, s32 cpu, struct task_struct *prev)
{
	// TODO to change ?
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_mine_running, struct task_struct *p){ /* removed for fifo */ }
void BPF_STRUCT_OPS(simple_mine_stopping, struct task_struct *p, bool runnable) { /* removed for fifo */ }
void BPF_STRUCT_OPS(simple_mine_enable, struct task_struct *p){ /* removed for fifo */ }

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_mine_init)
{
	if (!switch_partial)
		scx_bpf_switch_all();

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_mine_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops simple_mine_ops = {
	.select_cpu		= (void *)simple_mine_select_cpu,
	.enqueue		= (void *)simple_mine_enqueue,
	.dispatch		= (void *)simple_mine_dispatch,
	.running		= (void *)simple_mine_running,
	.stopping		= (void *)simple_mine_stopping,
	.enable			= (void *)simple_mine_enable,
	.init			= (void *)simple_mine_init,
	.exit			= (void *)simple_mine_exit,
	.flags			= SCX_OPS_ENQ_LAST | SCX_OPS_ENQ_EXITING | SCX_OPS_KEEP_BUILTIN_IDLE,
	.name			= "simple_mine",
};
