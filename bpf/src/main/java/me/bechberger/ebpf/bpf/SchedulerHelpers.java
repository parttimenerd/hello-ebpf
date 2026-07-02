// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFInterface;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_insert;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_nr_queued;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_nr_cpu_ids;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_select_cpu_dfl;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * BPF-side helper methods available to any class implementing {@link Scheduler}.
 *
 * <p>Split out from {@link Scheduler} so the callback surface stays focused on
 * the SCX ops (enqueue/dispatch/init/exit/…) while these convenience helpers —
 * DSQ inserts, CPU selection wrappers, weight-scaled arithmetic, task-flag
 * inspections, and the {@code scx_bpf_error} macro — live in one dedicated
 * interface.
 *
 * <p>All methods are {@code default} and translate to inlined BPF C via the
 * compiler plugin.  They are safe to call from any {@code @BPFFunction} or
 * struct_ops entry in a Scheduler implementation.
 */
@BPFInterface(
        before = """
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

                #define scx_bpf_error(fmt, args...)						\\
                ({										\\
                	static char ___fmt[] = fmt;						\\
                	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\\
                	_Pragma("GCC diagnostic push")						\\
                	_Pragma("GCC diagnostic ignored \\"-Wint-conversion\\"")			\\
                	___bpf_fill(___param, args);						\\
                	_Pragma("GCC diagnostic pop")						\\
                	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\\
                })

                /* Linux PF_KTHREAD flag, referenced by hasSchedulingConstraints() below.
                 * Emitted here (rather than relying on plugin constant emission from the
                 * PerProcessFlags inner class) so it precedes the first use in the file. */
                #ifndef PF_KTHREAD
                #define PF_KTHREAD 0x00200000
                #endif
                """
)
public interface SchedulerHelpers {

    /** Subset of Linux {@code PF_*} process flags actually referenced by hello-ebpf schedulers. */
    final class PerProcessFlags {
        /** I am a kernel thread. */
        public static final int PF_KTHREAD = 0x00200000;
    }

    /**
     * scx_bpf_error() wraps the scx_bpf_error_bstr() kfunc with variadic arguments
     * instead of an array of u64. Invoking this macro will cause the scheduler to
     * exit in an erroneous state, with diagnostic information being passed to the
     * user.
     */
    @BuiltinBPFFunction
    default void scx_bpf_error(String fmt, Object... args) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns {@code true} if the task has scheduling constraints that prevent it
     * from being placed on an arbitrary CPU: it is a kernel thread
     * ({@code PF_KTHREAD}) or its CPU affinity mask is narrower than the full set
     * of online CPUs.
     *
     * <p>Schedulers that scan a shared DSQ and target specific CPUs should check
     * this first.  A task with constraints should be dispatched unconditionally
     * (let the kernel handle placement) rather than skipped.
     *
     * @param p the task to inspect
     */
    @BPFFunction
    @AlwaysInline
    default boolean hasSchedulingConstraints(Ptr<TaskDefinitions.task_struct> p) {
        return ((p.val().flags & PerProcessFlags.PF_KTHREAD) != 0)
                || (p.val().nr_cpus_allowed != scx_bpf_nr_cpu_ids());
    }

    /**
     * Returns {@code true} if task {@code p} belongs to the process subtree
     * rooted at {@code targetTgid} (thread-group ID, i.e. the PID of the
     * process group leader).
     *
     * <p>Walks up the {@code real_parent} chain — up to 8 levels — comparing
     * each ancestor's {@code tgid} to {@code targetTgid}. This covers nested
     * child processes (e.g., a process spawned by the target process). All
     * threads of the target process share the same {@code tgid}, so this call
     * correctly matches every thread.
     *
     * <p>Example — skip chaos for tasks not belonging to the target process:
     * <pre>{@code
     *   if (!isDescendantOf(p, targetTgid)) {
     *       scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL.value(), SCX_SLICE_DFL.value(), 0);
     *       return;
     *   }
     * }</pre>
     *
     * @param p          the task to test
     * @param targetTgid the thread-group ID of the root process (as seen from
     *                   user space: {@code ProcessHandle.current().pid()})
     */
    @BPFFunction
    @AlwaysInline
    default boolean isDescendantOf(Ptr<TaskDefinitions.task_struct> p, int targetTgid) {
        Ptr<TaskDefinitions.task_struct> cur = p;
        for (@BoundedBy(8) int i = 0; i < 8; i++) {
            if (cur == null) return false;
            if (cur.val().tgid == targetTgid) return true;
            cur = cur.val().real_parent;
        }
        return false;
    }

    /**
     * Returns {@code true} if the task cannot be migrated to another CPU.
     *
     * <p>A task is considered non-migratable if its allowed CPU count is 1
     * ({@code nr_cpus_allowed == 1}) or if migration has been explicitly
     * disabled ({@code migration_disabled > 1}).  The threshold of {@code > 1}
     * accounts for the BPF prolog transiently calling {@code migrate_disable()}
     * for the current task (setting the field to 1), which would otherwise
     * produce a false positive for the task currently being observed.
     *
     * @param p the task to test
     */
    @BPFFunction
    @AlwaysInline
    default boolean isMigrationDisabled(Ptr<TaskDefinitions.task_struct> p) {
        return p.val().nr_cpus_allowed == 1 || p.val().migration_disabled > 1;
    }

    /**
     * Scales {@code value} proportionally to the task's scheduling weight.
     *
     * <p>Equivalent to {@code (value * p->scx.weight) / 100}.  The default
     * weight is 100 (nice 0), so normal tasks get {@code value} unchanged.
     * Higher-priority tasks (lower nice) get a larger result; lower-priority
     * tasks get a smaller result.  Useful for budget refill calculations.
     *
     * @param p     the task whose weight is used
     * @param value the base value to scale
     * @return      {@code value} scaled by the task's weight
     */
    @BPFFunction
    @AlwaysInline
    default long scaleByTaskWeight(Ptr<TaskDefinitions.task_struct> p, long value) {
        return (value * p.val().scx.weight) / 100;
    }

    /**
     * Inserts {@code p} into DSQ 0 (the conventional shared FIFO DSQ) with the
     * default slice, scaled inversely by the queue depth to avoid starvation.
     *
     * <p><b>Only safe for FIFO DSQs.</b>  Do not mix with
     * {@code scx_bpf_dsq_insert_vtime} on the same DSQ.
     *
     * @deprecated Prefer {@link me.bechberger.ebpf.bpf.sched.DispatchQueue#insertScaled} for new code.
     */
    @Deprecated
    @BPFFunction
    default void dsqInsert(Ptr<task_struct> p, long enq_flags) {
        @Unsigned int queued = scx_bpf_dsq_nr_queued(0L);
        long slice = queued > 0 ? SCX_SLICE_DFL.value() / queued : SCX_SLICE_DFL.value();
        scx_bpf_dsq_insert(p, 0L, slice, enq_flags);
    }

    /**
     * Selects a CPU using the kernel default without any pre-insertion.
     *
     * <p>Use this when tasks will be inserted later in {@code enqueue()}, especially
     * for vtime-ordered DSQs where FIFO pre-insertion would corrupt ordering.
     */
    @BPFFunction
    default int selectCpuDfl(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
    }

    /**
     * Selects a CPU for a waking task; pre-dispatches into {@code dsqId} when an idle
     * CPU is found (avoids a full enqueue/dispatch round-trip).
     *
     * <p><b>Only safe for FIFO DSQs.</b>  Do not use if {@code dsqId} is also written
     * with {@code scx_bpf_dsq_insert_vtime} — use {@link #selectCpuDfl} instead.
     *
     * @param dsqId FIFO DSQ to pre-dispatch into when an idle CPU is chosen
     */
    @BPFFunction
    default int selectCpuFifoIdleOrFallback(Ptr<task_struct> p, int prev_cpu, long wake_flags,
                                            @Unsigned long dsqId) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, dsqId, SCX_SLICE_DFL.value(), 0);
        }
        return cpu;
    }

    /**
     * Unsigned-safe {@code a < b} comparison for virtual time values.
     */
    @BPFFunction
    @AlwaysInline
    default boolean isSmaller(@Unsigned long a, @Unsigned long b) {
        return (long) (a - b) < 0;
    }

    /**
     * Charges execution time to {@code p}'s virtual time, scaled by the inverse
     * of the task's weight (so heavier tasks advance their vtime more slowly).
     *
     * <p>Call from {@link Scheduler#stopping(Ptr, boolean)}.
     */
    @BPFFunction
    default void vtimeCharge(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime +=
                (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100 / p.val().scx.weight;
    }
}
