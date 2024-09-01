// SPDX-License-Identifier: GPL-2.0
// See license at
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.h
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.bpf.c
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/include

package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInterface;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Ptr;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

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
                	
                """,
        after = """
                SCX_OPS_DEFINE(userland_ops,
                	       .select_cpu		= (void *)userland_select_cpu,
                	       .enqueue			= (void *)userland_enqueue,
                	       .dispatch		= (void *)userland_dispatch,
                	       .update_idle		= (void *)userland_update_idle,
                	       .init_task		= (void *)userland_init_task,
                	       .init			= (void *)userland_init,
                	       .exit			= (void *)userland_exit,
                	       .flags			= SCX_OPS_ENQ_LAST |
                					  SCX_OPS_KEEP_BUILTIN_IDLE,
                	       .name			= "userland");
                """
)
public interface Scheduler {

    /** No such process error code */
    final int ESRCH = 3;

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
            headerTemplate = "s32 BPF_STRUCT_OPS(userland_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)",
            addDefinition = false
    )
    int userland_select_cpu(Ptr<TaskDefinitions.task_struct> p, int prev_cpu, long wake_flags);

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(userland_enqueue, struct task_struct *p, u64 enq_flags)",
        addDefinition = false
    )
    void userland_enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags);

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(userland_dispatch, s32 cpu, struct task_struct *prev)",
            addDefinition = false
    )
    void userland_dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev);

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(userland_update_idle, s32 cpu, bool idle)",
            addDefinition = false
    )
    void userland_update_idle(int cpu, boolean idle);

    @BPFFunction(
            headerTemplate = "s32 BPF_STRUCT_OPS(userland_init_task, struct task_struct *p, struct scx_init_task_args *args)",
            addDefinition = false
    )
    int userland_init_task(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args);

    @BPFFunction(
            headerTemplate = "s32 BPF_STRUCT_OPS(userland_init)",
            addDefinition = false
    )
    int userland_init();

    @BPFFunction(
            headerTemplate = "int BPF_STRUCT_OPS(userland_exit, struct scx_exit_info *ei)",
            addDefinition = false
    )
    void userland_exit(Ptr<ScxDefinitions.scx_exit_info> ei);

    final int SCHED_EXT_UAPI_ID = 7;


    /**
     * Get the maximum PID that can be assigned to a process.
     *
     * @return the maximum PID
     */
    static int getPidMax() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/sys/kernel/pid_max"))) {
            String line = reader.readLine();
            return line != null ? Integer.parseInt(line.trim()) : -1;
        } catch (IOException | NumberFormatException e) {
            System.err.println("Error reading /proc/sys/kernel/pid_max: " + e.getMessage());
            return -1;
        }
    }
}
