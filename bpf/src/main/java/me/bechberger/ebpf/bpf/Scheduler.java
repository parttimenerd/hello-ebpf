// SPDX-License-Identifier: GPL-2.0
// See license at
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.h
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.bpf.c
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/include

package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Ptr;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.foreign.MemorySegment;

import static me.bechberger.ebpf.bpf.raw.Lib_2.bpf_link__destroy;
import static me.bechberger.ebpf.bpf.raw.Lib_2.bpf_map__attach_struct_ops;

/**
 * A sched-ext based scheduler
 * <p>
 * You can specify the scheduler name {@code Property(name = "sched_name", value = "...")}
 */
@BPFInterface(
        before = """
                void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym;
                
                /*
                 * Helper macro for initializing the fmt and variadic argument inputs to both
                 * bstr exit kfuncs. Callers to this function should use ___fmt and ___param to
                 * refer to the initialized list of inputs to the bstr kfunc.
                 */
                #define scx_bpf_bstr_preamble(fmt, args...)					\\
                	static char ___fmt[] = fmt;						\\
                	/*									\\
                	 * Note that __param[] must have at least one				\\
                	 * element to keep the verifier happy.					\\
                	 */									\\
                	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\\
                										\\
                	_Pragma("GCC diagnostic push")						\\
                	_Pragma("GCC diagnostic ignored \\"-Wint-conversion\\"")			\\
                	___bpf_fill(___param, args);						\\
                	_Pragma("GCC diagnostic pop")						\\
                
                
                /*
                 * scx_bpf_error() wraps the scx_bpf_error_bstr() kfunc with variadic arguments
                 * instead of an array of u64. Invoking this macro will cause the scheduler to
                 * exit in an erroneous state, with diagnostic information being passed to the
                 * user.
                 */
                #define scx_bpf_error(fmt, args...)						            \\
                ({										                            \\
                	scx_bpf_bstr_preamble(fmt, args)					            \\
                	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\\
                })
                struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
                struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
                void bpf_task_release(struct task_struct *p) __ksym;
                
                s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
                s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle) __ksym;
                void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
                void scx_bpf_dispatch_vtime(struct task_struct *p, u64 dsq_id, u64 slice, u64 vtime, u64 enq_flags) __ksym;
                u32 scx_bpf_dispatch_nr_slots(void) __ksym;
                void scx_bpf_dispatch_cancel(void) __ksym;
                bool scx_bpf_consume(u64 dsq_id) __ksym;
                u32 scx_bpf_reenqueue_local(void) __ksym;
                void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
                s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;
                void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;
                int bpf_iter_scx_dsq_new(struct bpf_iter_scx_dsq *it, u64 dsq_id, u64 flags) __ksym __weak;
                struct task_struct *bpf_iter_scx_dsq_next(struct bpf_iter_scx_dsq *it) __ksym __weak;
                void bpf_iter_scx_dsq_destroy(struct bpf_iter_scx_dsq *it) __ksym __weak;
                void scx_bpf_exit_bstr(s64 exit_code, char *fmt, unsigned long long *data, u32 data__sz) __ksym __weak;
                void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym;
                void scx_bpf_dump_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym __weak;
                u32 scx_bpf_cpuperf_cap(s32 cpu) __ksym __weak;
                u32 scx_bpf_cpuperf_cur(s32 cpu) __ksym __weak;
                void scx_bpf_cpuperf_set(s32 cpu, u32 perf) __ksym __weak;
                u32 scx_bpf_nr_cpu_ids(void) __ksym __weak;
                const struct cpumask *scx_bpf_get_possible_cpumask(void) __ksym __weak;
                const struct cpumask *scx_bpf_get_online_cpumask(void) __ksym __weak;
                void scx_bpf_put_cpumask(const struct cpumask *cpumask) __ksym __weak;
                const struct cpumask *scx_bpf_get_idle_cpumask(void) __ksym;
                const struct cpumask *scx_bpf_get_idle_smtmask(void) __ksym;
                void scx_bpf_put_idle_cpumask(const struct cpumask *cpumask) __ksym;
                bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) __ksym;
                s32 scx_bpf_pick_idle_cpu(const cpumask_t *cpus_allowed, u64 flags) __ksym;
                s32 scx_bpf_pick_any_cpu(const cpumask_t *cpus_allowed, u64 flags) __ksym;
                bool scx_bpf_task_running(const struct task_struct *p) __ksym;
                s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;
                struct rq *scx_bpf_cpu_rq(s32 cpu) __ksym;
                
                #define BPF_STRUCT_OPS(name, args...)						\\
                SEC("struct_ops/"#name)	BPF_PROG(name, ##args)
                
                
                /*
                 * Define sched_ext_ops. This may be expanded to define multiple variants for
                 * backward compatibility. See compat.h::SCX_OPS_LOAD/ATTACH().
                 */
                #define SCX_OPS_DEFINE(__name, ...)						\\
                	SEC(".struct_ops.link")							\\
                	struct sched_ext_ops __name = {						\\
                		__VA_ARGS__,							\\
                	};
                	
                #define BPF_STRUCT_OPS_SLEEPABLE(name, args...)					\\
                SEC("struct_ops.s/"#name)							\\
                BPF_PROG(name, ##args)
             
                	
                """,
        after = """
                SCX_OPS_DEFINE(sched_ops,
                	       .select_cpu		= (void *)sched_select_cpu,
                	       .enqueue			= (void *)sched_enqueue,
                	       .dispatch		= (void *)sched_dispatch,
                	       .update_idle		= (void *)sched_update_idle,
                	       .init_task		= (void *)sched_init_task,
                	       .init			= (void *)sched_init,
                	       .exit			= (void *)sched_exit,
                	       .running	        = (void *)simple_running,
                	       .enable          = (void *)simple_enable,
                	       .stopping        = (void *)simple_stopping,
                	       .flags			= SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE,
                	       .name			= "__property_sched_name");
                """
)
@Requires(sched_ext = true)
@PropertyDefinition(name = "sched_name", defaultValue = "hello", regexp = "[a-zA-Z0-9_]+")
public interface Scheduler {

    /** No such process error code */
    final int ESRCH = 3;

    final class PerProcessFlags {
        /** I'm a virtual CPU */
        public static final int PF_VCPU = 0x00000001;
        /** I am an IDLE thread */
        public static final int PF_IDLE = 0x00000002;
        /** Getting shut down */
        public static final int PF_EXITING = 0x00000004;
        /** Coredumps should ignore this task */
        public static final int PF_POSTCOREDUMP = 0x00000008;
        /** Task is an IO worker */
        public static final int PF_IO_WORKER = 0x00000010;
        /** I'm a workqueue worker */
        public static final int PF_WQ_WORKER = 0x00000020;
        /** Forked but didn't exec */
        public static final int PF_FORKNOEXEC = 0x00000040;
        /** Process policy on mce errors */
        public static final int PF_MCE_PROCESS = 0x00000080;
        /** Used super-user privileges */
        public static final int PF_SUPERPRIV = 0x00000100;
        /** Dumped core */
        public static final int PF_DUMPCORE = 0x00000200;
        /** Killed by a signal */
        public static final int PF_SIGNALED = 0x00000400;
        /** Allocating memory to free memory. See memalloc\_noreclaim\_save() */
        public static final int PF_MEMALLOC = 0x00000800;
        /** set\_user() noticed that RLIMIT\_NPROC was exceeded */
        public static final int PF_NPROC_EXCEEDED = 0x00001000;
        /** If unset the fpu must be initialized before use */
        public static final int PF_USED_MATH = 0x00002000;
        /** Kernel thread cloned from userspace thread */
        public static final int PF_USER_WORKER = 0x00004000;
        /** This thread should not be frozen */
        public static final int PF_NOFREEZE = 0x00008000;
        public static final int PF__HOLE__00010000 = 0x00010000;
        /** I am kswapd */
        public static final int PF_KSWAPD = 0x00020000;
        /** All allocations inherit GFP\_NOFS. See memalloc\_nfs\_save() */
        public static final int PF_MEMALLOC_NOFS = 0x00040000;
        /** All allocations inherit GFP\_NOIO. See memalloc\_noio\_save() */
        public static final int PF_MEMALLOC_NOIO = 0x00080000;
        /** Throttle writes only against the bdi I write to, I am cleaning dirty pages from some other bdi. */
        public static final int PF_LOCAL_THROTTLE = 0x00100000;
        /** I am a kernel thread */
        public static final int PF_KTHREAD = 0x00200000;
        /** Randomize virtual address space */
        public static final int PF_RANDOMIZE = 0x00400000;
        /** All allocation requests will clear \_\_GFP\_DIRECT\_RECLAIM */
        public static final int PF_MEMALLOC_NORECLAIM = 0x00800000;
        /** All allocation requests will inherit \_\_GFP\_NOWARN */
        public static final int PF_MEMALLOC_NOWARN = 0x01000000;
        public static final int PF__HOLE__02000000 = 0x02000000;
        /** Userland is not allowed to meddle with cpus\_mask */
        public static final int PF_NO_SETAFFINITY = 0x04000000;
        /** Early kill for mce process policy */
        public static final int PF_MCE_EARLY = 0x08000000;
        /** Allocations constrained to zones which allow long term pinning. See memalloc\_pin\_save() */
        public static final int PF_MEMALLOC_PIN = 0x10000000;
        /** plug has ts that needs updating */
        public static final int PF_BLOCK_TS = 0x20000000;
        public static final int PF__HOLE__40000000 = 0x40000000;
        /** This thread called freeze\_processes() and should not be frozen */
        public static final int PF_SUSPEND_TASK = 0x80000000;
    }

    /*
     * scx_bpf_error() wraps the scx_bpf_error_bstr() kfunc with variadic arguments
     * instead of an array of u64. Invoking this macro will cause the scheduler to
     * exit in an erroneous state, with diagnostic information being passed to the
     * user.
     */
    @BuiltinBPFFunction
    default void scx_bpf_error(String fmt, Object... args) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BPFFunction(
            headerTemplate = "s32 BPF_STRUCT_OPS(sched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)",
            addDefinition = false
    )
    default int selectCPU(Ptr<TaskDefinitions.task_struct> p, int prev_cpu, long wake_flags) {
        return 0;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(sched_enqueue, struct task_struct *p, u64 enq_flags)",
        addDefinition = false
    )
    void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags);

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(sched_dispatch, s32 cpu, struct task_struct *prev)",
            addDefinition = false
    )
    default void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        return;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(sched_update_idle, s32 cpu, bool idle)",
            addDefinition = false
    )
    default void updateIdle(int cpu, boolean idle) {
        return;
    }

    @BPFFunction(
            headerTemplate = "s32 BPF_STRUCT_OPS(sched_init_task, struct task_struct *p, struct scx_init_task_args *args)",
            addDefinition = false
    )
    default int initTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args) {
        return 0;
    }

    @BPFFunction(
            headerTemplate = "s32 BPF_STRUCT_OPS_SLEEPABLE(sched_init)",
            addDefinition = false
    )
    default int init() {
        return 0;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(sched_exit, struct scx_exit_info *ei)",
            addDefinition = false
    )
    default void exit(Ptr<ScxDefinitions.scx_exit_info> ei) {
        return;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(simple_running, struct task_struct *p)",
            addDefinition = false
    )
    default void running(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(simple_enable, struct task_struct *p)",
            addDefinition = false
    )
    default void enable(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)",
            addDefinition = false
    )
    default void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) {
        return;
    }

    final int SCHED_EXT_UAPI_ID = 7;

    default void attachScheduler() {

        BPFProgram bpfProgram = (BPFProgram)this;
        try {
            bpfProgram.attachStructOps("sched_ops");
        } catch (BPFProgram.BPFAttachError err) {
            throw new BPFError("Could not attach scheduler, " +
                    "maybe stop the current sched-ext scheduler via 'systemctl stop scx'", err);
        }
        if (!isSchedulerAttachedProperly()) {

            throw new BPFError("Scheduler not attached properly, maybe some methods are incorrectly implemented");
        }
    }

    default String getSchedulerName() {
        return ((BPFProgram)this).getPropertyValue("sched_name");
    }

    /**
     * Check via /sys/kernel/sched_ext/root/ops whether the scheduler is attached properly.
     */
    default boolean isSchedulerAttachedProperly() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/sys/kernel/sched_ext/root/ops"))) {
            String line = reader.readLine();
            return line.equals(getSchedulerName());
        } catch (IOException e) {
            return false;
        }
    }
}
