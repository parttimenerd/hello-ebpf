#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

s64 _exitCode SEC(".data");
s64 _exitKind SEC(".data");

/*
 * scx_bpf_error() wraps scx_bpf_error_bstr() with variadic args instead
 * of a u64 array. Invoking it exits the scheduler in an erroneous state
 * and passes diagnostic info back to userspace.
 *
 * The __ksym decl is required because the macro expands to a direct call
 * to scx_bpf_error_bstr that the plugin's per-call kfunc-decl emission
 * cannot see through (macros expand after codegen).
 */
void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym;

#define scx_bpf_error(fmt, args...)						\
({										\
	static char ___fmt[] = fmt;						\
	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")			\
	___bpf_fill(___param, args);						\
	_Pragma("GCC diagnostic pop")						\
	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\
})

/* Linux PF_KTHREAD flag, referenced by hasSchedulingConstraints() below.
 * Emitted here (rather than relying on plugin constant emission from the
 * PerProcessFlags inner class) so it precedes the first use in the file. */
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif


#define PF_KTHREAD 2097152

__always_inline bool hasSchedulingConstraints(struct task_struct *p);

__always_inline bool isDescendantOf(struct task_struct *p, s32 targetTgid);

__always_inline bool isMigrationDisabled(struct task_struct *p);

__always_inline s64 scaleByTaskWeight(struct task_struct *p, s64 value);

__always_inline int dsqInsert(struct task_struct *p, s64 enq_flags);

__always_inline s32 selectCpuDfl(struct task_struct *p, s32 prev_cpu, s64 wake_flags);

__always_inline s32 selectCpuFifoIdleOrFallback(struct task_struct *p, s32 prev_cpu, s64 wake_flags, u64 dsqId);

__always_inline bool isSmaller(u64 a, u64 b);

__always_inline int vtimeCharge(struct task_struct *p);

struct task_struct;

__always_inline int dsqInsert(struct task_struct *p, s64 enq_flags);
__always_inline bool hasSchedulingConstraints(struct task_struct *p);
__always_inline bool isDescendantOf(struct task_struct *p, s32 targetTgid);
__always_inline bool isMigrationDisabled(struct task_struct *p);
__always_inline bool isSmaller(u64 a, u64 b);
__always_inline s64 scaleByTaskWeight(struct task_struct *p, s64 value);
__always_inline s32 selectCpuDfl(struct task_struct *p, s32 prev_cpu, s64 wake_flags);
__always_inline s32 selectCpuFifoIdleOrFallback(struct task_struct *p, s32 prev_cpu, s64 wake_flags, u64 dsqId);
__always_inline int vtimeCharge(struct task_struct *p);


#define SHARED_DSQ_ID 0L



char _license[] SEC("license") = "GPL";

SEC("struct_ops/enqueue") void BPF_PROG(sched_enqueue, struct task_struct *p, __u64 enq_flags) {
  #line 39 "MinimalScheduler.java"
  scx_bpf_dsq_insert(p, SHARED_DSQ_ID, scx_bpf_dsq_nr_queued(SHARED_DSQ_ID) > 0   ? SCX_SLICE_DFL / (u64)scx_bpf_dsq_nr_queued(SHARED_DSQ_ID)   : SCX_SLICE_DFL, enq_flags);
}

SEC("struct_ops/dispatch") void BPF_PROG(sched_dispatch, s32 cpu, struct task_struct *prev) {
  #line 44 "MinimalScheduler.java"
  scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

__always_inline int dsqInsert(struct task_struct *p, s64 enq_flags) {
  #line 187 "SchedulerHelpers.java"
  u32 queued = scx_bpf_dsq_nr_queued(0L);
  #line 188 "SchedulerHelpers.java"
  s64 slice = queued > 0 ? (long)(SCX_SLICE_DFL) / queued : (long)(SCX_SLICE_DFL);
  #line 189 "SchedulerHelpers.java"
  scx_bpf_dsq_insert(p, 0L, slice, enq_flags);
  return 0;
}

SEC("struct_ops/exit") void BPF_PROG(sched_exit, struct scx_exit_info *ei) {
  #line 82 "SchedulerBase.java"
  _exitCode = BPF_CORE_READ(ei, exit_code);
  #line 83 "SchedulerBase.java"
  _exitKind = (s64)(long)(BPF_CORE_READ(ei, kind));
}

__always_inline bool hasSchedulingConstraints(struct task_struct *p) {
  #line 100 "SchedulerHelpers.java"
  return ((BPF_CORE_READ(p, flags) & PF_KTHREAD) != 0) || (BPF_CORE_READ(p, nr_cpus_allowed) != scx_bpf_nr_cpu_ids());
}

#define SHARED_DSQ_ID 0L
SEC("struct_ops.s/init") s32 BPF_PROG(sched_init) {
  #line 73 "SchedulerBase.java"
  return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

__always_inline bool isDescendantOf(struct task_struct *p, s32 targetTgid) {
  #line 130 "SchedulerHelpers.java"
  struct task_struct *cur = p;
  #line 131 "SchedulerHelpers.java"
  for (s32 i = 0; i < 8; i++) {
    if (!(i < 8)) {
      break;
    }
    #line 132 "SchedulerHelpers.java"
    if ((cur == NULL)) {
      return 0;
    }
    #line 133 "SchedulerHelpers.java"
    if ((BPF_CORE_READ(cur, tgid) == targetTgid)) {
      return 1;
    }
    #line 134 "SchedulerHelpers.java"
    cur = BPF_CORE_READ(cur, real_parent);
  }
  #line 136 "SchedulerHelpers.java"
  return 0;
}

__always_inline bool isMigrationDisabled(struct task_struct *p) {
  #line 154 "SchedulerHelpers.java"
  return (BPF_CORE_READ(p, nr_cpus_allowed) == 1) || (BPF_CORE_READ(p, migration_disabled) > 1);
}

__always_inline bool isSmaller(u64 a, u64 b) {
  #line 230 "SchedulerHelpers.java"
  return ((s64)(a - b)) < 0;
}

__always_inline s64 scaleByTaskWeight(struct task_struct *p, s64 value) {
  #line 172 "SchedulerHelpers.java"
  return (value * BPF_CORE_READ(p, scx.weight)) / 100;
}

__always_inline s32 selectCpuDfl(struct task_struct *p, s32 prev_cpu, s64 wake_flags) {
  #line 200 "SchedulerHelpers.java"
  bool is_idle = 0;
  #line 201 "SchedulerHelpers.java"
  return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &(is_idle));
}

__always_inline s32 selectCpuFifoIdleOrFallback(struct task_struct *p, s32 prev_cpu, s64 wake_flags, u64 dsqId) {
  #line 216 "SchedulerHelpers.java"
  bool is_idle = 0;
  #line 217 "SchedulerHelpers.java"
  s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &(is_idle));
  #line 218 "SchedulerHelpers.java"
  if ((is_idle)) {
    #line 219 "SchedulerHelpers.java"
    scx_bpf_dsq_insert(p, dsqId, (long)(SCX_SLICE_DFL), 0);
  }
  #line 221 "SchedulerHelpers.java"
  return cpu;
}

__always_inline int vtimeCharge(struct task_struct *p) {
  #line 241 "SchedulerHelpers.java"
  (*(p)).scx.dsq_vtime += (((long)(SCX_SLICE_DFL) - BPF_CORE_READ(p, scx.slice)) * 100) / BPF_CORE_READ(p, scx.weight);
  return 0;
}




SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue = (void *)sched_enqueue,
    .dispatch = (void *)sched_dispatch,
    .init = (void *)sched_init,
    .exit = (void *)sched_exit,
    .timeout_ms = 10000,
    .name = "minimal_scheduler",
    .flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (0),
};
