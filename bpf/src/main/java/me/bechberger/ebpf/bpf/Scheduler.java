// SPDX-License-Identifier: GPL-2.0
// See license at
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.h
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.bpf.c
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/include

package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.BoundedBy;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.runtime.BpfDefinitions;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.runtime.runtime.cpumask;
import me.bechberger.ebpf.type.Ptr;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.function.Consumer;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A sched-ext based scheduler.
 *
 * <p>Specify the scheduler name with {@code @Property(name = "sched_name", value = "...")}.
 *
 * <h2>Properties</h2>
 * <ul>
 *   <li>{@code sched_name} — name registered with the kernel (visible in
 *       {@code /sys/kernel/sched_ext/root/ops}).  Must match {@code [a-zA-Z0-9_]+}.
 *       Default: {@code "hello"}.</li>
 *   <li>{@code timeout_ms} — kernel watchdog interval in milliseconds.  If the
 *       scheduler does not dispatch any task for this long, the kernel force-unloads
 *       it with {@code SCX_EXIT_ERROR_STALL}.  Default: {@code 30000} (30 s).
 *       Set to a large value (e.g. {@code 60000}) for production; for interactive
 *       debugging a short value (e.g. {@code 5000}) is safer so a stuck scheduler
 *       does not freeze the system.  There is no way to disable the watchdog
 *       entirely.</li>
 *   <li>{@code extra_flags} — additional {@code SCX_OPS_*} flags OR-ed into
 *       {@code sched_ext_ops.flags}.  Default: {@code 0}.  Example:
 *       {@code @Property(name = "extra_flags", value = "SCX_OPS_ENQ_MIGRATION_DISABLED")}.
 *   </li>
 * </ul>
 *
 * <p><b>cpumask import note:</b> Methods that deal with {@code cpumask} (e.g.
 * {@link ScxDefinitions#scx_bpf_get_possible_cpumask()}, {@link ScxDefinitions#scx_bpf_pick_idle_cpu}) return
 * {@code Ptr<cpumask>}.  The {@code cpumask} type lives in a deeply-nested package; add
 * this import to any scheduler class that uses it:
 * <pre>{@code import me.bechberger.ebpf.runtime.runtime.cpumask;}</pre>
 *
 * <p>Based on the Linux sched_ext sources.
 */
@me.bechberger.ebpf.annotations.bpf.StructOps(
        value = "sched_ext_ops",
        instanceName = "sched_ops",
        emittedNamePrefix = "sched_")
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

                #define scx_bpf_bstr_preamble(fmt, args...)					\\
                	static char ___fmt[] = fmt;						\\
                	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\\
                	_Pragma("GCC diagnostic push")						\\
                	_Pragma("GCC diagnostic ignored \\"-Wint-conversion\\"")			\\
                	___bpf_fill(___param, args);						\\
                	_Pragma("GCC diagnostic pop")

                #define scx_bpf_error(fmt, args...)						\\
                ({										\\
                	scx_bpf_bstr_preamble(fmt, args)					\\
                	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\\
                })
                """
)
@Requires(sched_ext = true)
@PropertyDefinition(name = "sched_name", defaultValue = "hello", regexp = "[a-zA-Z0-9_]+")
@PropertyDefinition(name = "timeout_ms", defaultValue = "30000", regexp = "[1-9]\\d*")
@PropertyDefinition(name = "extra_flags", defaultValue = "0", regexp = "[A-Z0-9_| ()]+")
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
     * Selects the target CPU for a task being woken up.
     *
     * <p>Called before the task is enqueued.  Returning an idle CPU causes the kernel
     * to attempt a fast-path dispatch directly to {@code SCX_DSQ_LOCAL} of that CPU —
     * use {@link #selectCpuDefault} or {@link #selectCpuFifoIdleOrFallback} to take
     * advantage of this.  If you pre-insert the task into a DSQ here, {@link #enqueue}
     * will <em>not</em> be called.
     *
     * <p>This decision is <b>not final</b>: the kernel may move the task to a different
     * CPU at dispatch time if affinity constraints require it.  Use the result as a hint,
     * not a guarantee.
     *
     * <p>The default implementation always returns 0 (CPU 0), which is safe but
     * suboptimal.  Most schedulers should delegate to {@link #selectCpuDefault} or
     * {@link #selectCpuFifoIdleOrFallback}.
     *
     * @param p          task being woken up
     * @param prev_cpu   CPU the task was running on before sleeping
     * @param wake_flags {@code SCX_WAKE_*} flags describing the wake-up reason
     * @return           preferred target CPU; will be passed back as {@code prev_cpu}
     *                   in the next {@code selectCPU} call if the task doesn't migrate
     */
    default int selectCPU(Ptr<TaskDefinitions.task_struct> p, int prev_cpu, long wake_flags) {
        return 0;
    }

    /**
     * Enqueues a task into the BPF scheduler.
     *
     * <p><b>Ownership:</b> when this is called, the scheduler <em>owns</em> the task.
     * It <em>must</em> be placed into a DSQ before returning — either by calling
     * {@link #dsqInsert}, {@link #vtimeEnqueue}, {@code scx_bpf_dsq_insert}, or
     * {@code scx_bpf_dsq_insert_vtime}.  Failing to enqueue leaves the task orphaned
     * and will trigger a watchdog stall.
     *
     * <p>This is the <b>only mandatory callback</b>.  All other callbacks have
     * no-op defaults.
     *
     * @param p          task being handed to the scheduler
     * @param enq_flags  {@code SCX_ENQ_*} flags; check {@code SCX_ENQ_WAKEUP} to
     *                   distinguish fresh wakeups from re-enqueues after preemption
     */
    void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags);

    /**
     * Dispatches tasks from DSQs to the CPU's local run queue.
     *
     * <p>Called when a CPU's local run queue is empty and needs more work.  The
     * implementation should call {@link ScxDefinitions#scx_bpf_dsq_move_to_local} one or
     * more times to pull tasks from a DSQ into the CPU's local queue.
     *
     * <p>It is <b>safe to return without dispatching anything</b> — the kernel will
     * keep calling {@code dispatch} until either a task is found or the CPU goes idle.
     * This means you can implement round-robin, rate-limiting, or priority gating here
     * without fear of stalling the CPU.
     *
     * <p>{@link SchedulerBase} provides a default implementation that drains
     * {@code SHARED_DSQ_ID} to the local queue.  {@link PerCpuSchedulerBase} drains the
     * per-CPU DSQ first, then falls back to the shared DSQ.
     *
     * @param cpu   the CPU requesting more work
     * @param prev  the task that was just descheduled (may be {@code null})
     */
    default void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        return;
    }

    /**
     * Updates the idle state of a CPU.
     *
     * <p><b>Warning:</b> implementing this op disables the built-in idle CPU tracking
     * ({@code SCX_OPS_KEEP_BUILTIN_IDLE} is set by default in the {@code flags} field,
     * but explicit tracking here overrides that bookkeeping for this CPU).  If you
     * implement {@code updateIdle} you are responsible for tracking which CPUs are idle
     * and for making them available to {@code scx_bpf_pick_idle_cpu}.
     *
     * <p>Most schedulers do <b>not</b> need this — the default no-op inherits the
     * kernel's built-in idle tracking.
     *
     * @param cpu   CPU whose idle state changed
     * @param idle  {@code true} = entering idle; {@code false} = leaving idle
     */
    default void updateIdle(int cpu, boolean idle) {
        return;
    }

    /**
     * Initializes per-task scheduler state when a task first enters SCX.
     *
     * <p>Called either when the scheduler is loaded (for all existing tasks) or when
     * a new task is forked.  Use this to allocate or initialise any per-task data
     * you store in a {@link me.bechberger.ebpf.bpf.map.BPFTaskStorage} map.
     *
     * <p>Always paired with a matching {@link #exitTask} call.  If you return a
     * negative errno here, the task is not admitted to the scheduler and
     * {@link #exitTask} will still be called (with {@code args.cancelled == true}).
     *
     * @param p    task entering the scheduler
     * @param args {@code args.fork} is {@code true} when this is a newly forked task,
     *             {@code false} when the scheduler was just loaded
     * @return     0 on success, negative errno on failure
     */
    default int initTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args) {
        return 0;
    }

    /**
     * Initializes the BPF scheduler.
     *
     * <p>Called once during scheduler attachment, before any tasks are admitted.
     * This is the right place to create DSQs via {@code scx_bpf_create_dsq}.
     *
     * <p>{@link SchedulerBase} provides a default that creates {@code SHARED_DSQ_ID}.
     * {@link PerCpuSchedulerBase} overrides this to also create one DSQ per CPU.
     * Override this method (calling {@code super.init()} if needed) to create additional
     * custom DSQs.
     *
     * @return 0 on success, negative errno on failure (causes scheduler load to abort)
     */
    @me.bechberger.ebpf.annotations.bpf.Sleepable
    default int init() {
        return 0;
    }

    /**
     * Called when the scheduler is about to be unloaded.
     *
     * <p>Receives an {@link ScxDefinitions.scx_exit_info} struct that describes why
     * the scheduler is exiting ({@code ei.exit_code}, {@code ei.kind}).  Use it to log
     * a final message or capture state before the BPF program is torn down.
     *
     * <p>{@link SchedulerBase} overrides this to capture {@code ei.exit_code} into
     * a {@link GlobalVariable} so it can be read from Java after detach via
     * {@link SchedulerBase#getExitCode()}.  Override and call {@code super.exit(ei)}
     * to add custom cleanup without losing the exit-code capture.
     *
     * @param ei scheduler exit information from the kernel
     */
    default void exit(Ptr<ScxDefinitions.scx_exit_info> ei) {
        return;
    }

    /**
     * Notifies that a task has entered the runnable state but is not yet on a CPU.
     *
     * <p>Called <em>before</em> {@link #enqueue}.  Use for per-task bookkeeping such
     * as recording wakeup timestamps for latency tracking or incrementing wakeup
     * counters.  The task is <b>not yet owned</b> by the scheduler here — do not insert
     * it into a DSQ from this callback.
     *
     * <p>Contrast with {@link #running}: {@code runnable} fires when the task becomes
     * eligible to run; {@code running} fires when it actually starts executing on a CPU.
     *
     * @param p          task transitioning to runnable
     * @param enq_flags  {@code SCX_ENQ_*} flags describing the wakeup reason
     */
    default void runnable(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enq_flags) {
        return;
    }

    /**
     * Notifies that a task has started executing on a CPU.
     *
     * <p>Paired with {@link #stopping}: {@code running} fires when the task is
     * context-switched <em>in</em>; {@code stopping} fires when it is context-switched
     * <em>out</em>.  Use together to measure per-task on-CPU time or to charge budget.
     *
     * <p>Contrast with {@link #runnable}: {@code runnable} fires when the task becomes
     * eligible to run (may be long before it actually gets a CPU); {@code running} fires
     * at the exact moment it starts executing.
     *
     * @param p task that started running
     */
    default void running(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }

    /**
     * Enables scheduling for a task.
     *
     * <p>Called on {@code p} any time it enters SCX.  Always paired with a matching
     * {@link #disable(Ptr)} call.
     *
     * @param p task entering SCX scheduling
     */
    default void enable(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }
    
    /**
     * Disables BPF scheduling for a task.
     *
     * <p>Called when {@code p} is exiting, leaving SCX, or the scheduler is being unloaded.
     * Always paired with a prior {@link #enable(Ptr)} call.
     *
     * @param p task leaving SCX scheduling
     */
    default void disable(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }

    /**
     * Notifies that a task is being descheduled from its CPU.
     *
     * <p>Paired with {@link #running}: called when the task is context-switched out.
     * {@code runnable} indicates whether the task is still runnable (it will be
     * re-enqueued) or has blocked (it will not appear in {@link #enqueue} again until
     * it next wakes up).
     *
     * <p>The typical use case is updating vtime:
     * <pre>{@code
     * \@Override
     * public void stopping(Ptr<task_struct> p, boolean runnable) {
     *     vtimeCharge(p);  // charge elapsed CPU time to p's vtime
     * }
     * }</pre>
     *
     * @param p        task being descheduled
     * @param runnable {@code true} if the task will be re-enqueued (preempted);
     *                 {@code false} if it is blocking (going to sleep)
     */
    default void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) {
        return;
    }

    /**
     * Removes a task from the BPF scheduler before it has been dispatched.
     *
     * <p>Called when the kernel wants to take back ownership of {@code p} — typically
     * to update its scheduling properties (priority, affinity) or because it is being
     * migrated.  The task will be re-enqueued via {@link #enqueue} after the update.
     *
     * <p><b>Implementation note:</b> The kernel gracefully ignores spurious dispatches
     * from the BPF side, so it is safe to leave this as a no-op.  However, if the
     * scheduler has cached the task's position (e.g. in a vtime DSQ), not implementing
     * {@code dequeue} means the task may run at its old priority after the update —
     * which can cause confusing behaviour such as a priority-raised task that still runs
     * slowly.
     *
     * @param p         task being removed
     * @param deq_flags {@code SCX_DEQ_*} flags describing why the task is being removed
     */
    default void dequeue(Ptr<TaskDefinitions.task_struct> p, @Unsigned long deq_flags) {
        return;
    }

    /**
     * Periodic tick fired on each CPU that is running an SCX task.
     *
     * <p>Called approximately once per Hz (typically 250–1000 Hz depending on kernel
     * config).  A common use is to implement time-slice expiry: if the current task has
     * exceeded its budget, set {@code p.val().scx.slice = 0} to force an immediate
     * dispatch cycle on this CPU.
     *
     * <pre>{@code
     * \@Override
     * public void tick(Ptr<task_struct> p) {
     *     if (p.val().scx.slice > myBudget) {
     *         p.val().scx.slice = 0;  // trigger immediate reschedule
     *     }
     * }
     * }</pre>
     *
     * @param p task currently running on this CPU
     */
    default void tick(Ptr<TaskDefinitions.task_struct> p) {
        return;
    }

    /**
     * A task has transitioned from runnable to blocked (quiescent).
     *
     * <p>The counterpart to {@link #runnable}: called when {@code p} stops being
     * runnable without being dispatched (e.g. it called {@code sleep()}, waited on a
     * mutex, or was killed).  Use to clean up any per-task state that was set up in
     * {@link #runnable}.
     *
     * @param p          task transitioning to blocked/quiescent
     * @param enq_flags  {@code SCX_ENQ_*} flags (same flags that were passed to
     *                   {@link #runnable} when the task last became runnable)
     */
    default void quiescent(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enq_flags) {
    }

    /**
     * A CPU has come online and is now available for scheduling.
     *
     * <p>Called when a CPU is hot-plugged in or brought out of an offline state.
     * Use to initialise any per-CPU data structures that were torn down in
     * {@link #cpuOffline}.
     *
     * @param cpu the CPU that just came online
     */
    default void cpuOnline(int cpu) {
    }

    /**
     * A CPU is going offline and will no longer be available for scheduling.
     *
     * <p>Called when a CPU is hot-plugged out or about to enter an offline state.
     * Use to drain any per-CPU DSQs or release per-CPU state before the CPU
     * disappears.
     *
     * @param cpu the CPU that is going offline
     */
    default void cpuOffline(int cpu) {
    }

    /**
     * Determines whether task {@code a} should run before task {@code b} under
     * <a href="https://docs.kernel.org/scheduler/sched-ext.html">core scheduling</a>.
     *
     * <p>Core scheduling groups tasks into "cookies"; two tasks with the same cookie
     * can share a hyperthreaded core, while tasks with different cookies cannot.
     * This op is only called when {@code CONFIG_SCHED_CORE} is enabled and the two
     * tasks are in the same scheduling class.
     *
     * <p>Return {@code true} if {@code a} should run before {@code b}.  The default
     * (returning {@code false}) defers to the kernel's built-in ordering.
     *
     * @param a first candidate task
     * @param b second candidate task
     * @return  {@code true} if {@code a} has scheduling priority over {@code b}
     */
    default boolean coreSchedBefore(Ptr<TaskDefinitions.task_struct> a, Ptr<TaskDefinitions.task_struct> b) {
        return false;
    }

    /**
     * Emits a global scheduler-state dump line to the sched-ext debug interface.
     *
     * <p>Called when the kernel's sched-ext debug dump is triggered (e.g. via
     * {@code /sys/kernel/debug/sched/sched_debug}).  Use {@code scx_bpf_dump_bstr}
     * to write formatted output.
     *
     * @param dump_ctx dump context — pass to {@code scx_bpf_dump_bstr} for structured output
     */
    default void dump(Ptr<ScxDefinitions.scx_dump_ctx> dump_ctx) {
    }

    /**
     * Emits per-CPU state to the sched-ext debug dump.
     *
     * <p>Called once per CPU during a debug dump.
     *
     * @param dump_ctx dump context
     * @param cpu      CPU being reported
     * @param idle     {@code true} if the CPU is currently idle
     */
    default void dumpCpu(Ptr<ScxDefinitions.scx_dump_ctx> dump_ctx, int cpu, boolean idle) {
    }

    /**
     * Emits per-task state to the sched-ext debug dump.
     *
     * <p>Called once per task queued in the scheduler during a debug dump.
     *
     * @param dump_ctx dump context
     * @param p        task being reported
     */
    default void dumpTask(Ptr<ScxDefinitions.scx_dump_ctx> dump_ctx, Ptr<TaskDefinitions.task_struct> p) {
    }

    /**
     * Initialises scheduler state for a newly created cgroup.
     *
     * <p>Only relevant if the scheduler uses cgroup-based scheduling hierarchies.
     * Called once when a cgroup is created.
     *
     * @param cgrp the new cgroup
     * @param args initialisation arguments
     * @return     0 on success, negative errno on failure
     */
    default int cgroupInit(Ptr<runtime.cgroup> cgrp, Ptr<ScxDefinitions.scx_cgroup_init_args> args) {
        return 0;
    }

    /**
     * Tears down scheduler state for a cgroup that is being destroyed.
     *
     * @param cgrp the cgroup being destroyed
     */
    default void cgroupExit(Ptr<runtime.cgroup> cgrp) {
    }

    /**
     * Prepares to move task {@code p} from cgroup {@code from} to cgroup {@code to}.
     *
     * <p>Called before the move takes effect.  A matching {@link #cgroupMove} (on
     * success) or {@link #cgroupCancelMove} (on failure) will always follow.
     *
     * @param p    task being moved
     * @param from source cgroup
     * @param to   destination cgroup
     * @return     0 to allow the move, negative errno to reject it
     */
    default int cgroupPrepMove(Ptr<TaskDefinitions.task_struct> p,
                               Ptr<runtime.cgroup> from, Ptr<runtime.cgroup> to) {
        return 0;
    }

    /**
     * Cancels a pending cgroup move that was prepared by {@link #cgroupPrepMove}.
     *
     * <p>Called if the move was rejected after {@link #cgroupPrepMove} returned 0,
     * allowing the scheduler to undo any state allocated during prep.
     *
     * @param p task whose cgroup move was cancelled
     */
    default void cgroupCancelMove(Ptr<TaskDefinitions.task_struct> p) {
    }

    /**
     * Completes the cgroup move that was prepared by {@link #cgroupPrepMove}.
     *
     * <p>Called after the move has been committed.  Update per-task cgroup references
     * here.
     *
     * @param p task that was moved to a new cgroup
     */
    default void cgroupMove(Ptr<TaskDefinitions.task_struct> p) {
    }

    /**
     * Notifies that a cgroup's CPU weight has changed.
     *
     * <p>Called when the cgroup's {@code cpu.weight} is written.  Schedulers that
     * implement cgroup-proportional scheduling should refresh their weight caches here.
     *
     * @param cgrp   the cgroup whose weight changed
     * @param weight new CPU weight (proportional to priority, default 100)
     */
    default void cgroupSetWeight(Ptr<runtime.cgroup> cgrp, @Unsigned int weight) {
    }

    /**
     * Notifies that a cgroup's CPU bandwidth limit has changed.
     *
     * <p>Called when the cgroup's {@code cpu.max} is written.  Relevant only for
     * schedulers that enforce bandwidth limits per cgroup.
     *
     * @param cgrp       the cgroup whose bandwidth changed
     * @param period_us  bandwidth period in microseconds
     * @param quota_us   maximum CPU time allowed per period, in microseconds
     * @param burst_us   maximum burst above quota, in microseconds
     */
    default void cgroupSetBandwidth(Ptr<runtime.cgroup> cgrp,
                                    @Unsigned long period_us,
                                    @Unsigned long quota_us,
                                    @Unsigned long burst_us) {
    }

    /**
     * A CPU is being acquired by the scheduler after being released.
     *
     * <p>Called when a CPU transitions back to SCX control after being preempted by an
     * RT or deadline task.  Paired with {@link #cpuRelease}.  Use to restore per-CPU
     * state (e.g. reset credit counters) or kick the CPU to resume dispatching.
     *
     * @param cpu  CPU being acquired back
     * @param args acquire arguments (currently empty, reserved for future use)
     */
    default void cpuAcquire(int cpu, Ptr<ScxDefinitions.scx_cpu_acquire_args> args) {
    }

    /**
     * A CPU is being released from the scheduler due to higher-priority preemption.
     *
     * @param cpu  CPU being released.
     * @param args release arguments: {@code args.reason} ({@link ScxDefinitions#scx_cpu_preempt_reason})
     *             and {@code args.task} (the preempting task, if any).
     *
     * <p>Called when an RT or deadline task preempts the current SCX task.
     * The typical implementation re-enqueues locally runnable tasks so they
     * can be picked up once the preemption ends:
     * <pre>{@code
     * \@Override
     * public void cpuRelease(int cpu, Ptr<ScxDefinitions.scx_cpu_release_args> args) {
     *     scx_bpf_reenqueue_local();
     * }
     * }</pre>
     */
    default void cpuRelease(int cpu, Ptr<ScxDefinitions.scx_cpu_release_args> args) {
    }

    /**
     * A task is voluntarily yielding its CPU.
     *
     * @param from the yielding task
     * @param to   the task being yielded to, or {@code null} for a general yield
     * @return     {@code true} to honour the yield (reschedule {@code from});
     *             {@code false} to ignore it (let {@code from} keep running)
     *
     * <p>Called when a task calls {@code sched_yield()}.  Returning {@code false}
     * keeps the task running, which is fine for most schedulers.  Returning
     * {@code true} forces an immediate dispatch cycle.
     *
     * <p>Available since kernel 6.12.
     */
    default boolean yield(Ptr<TaskDefinitions.task_struct> from, Ptr<TaskDefinitions.task_struct> to) {
        return false;
    }

    /**
     * The weight of a task has changed.
     *
     * @param p      the task whose weight changed
     * @param weight new weight value (proportional to priority)
     *
     * <p>Called when a task's scheduling weight is updated (e.g. via
     * {@code setpriority(2)} or cgroup CPU weight changes).  Schedulers that
     * cache weight in per-task storage should refresh it here.
     */
    default void setWeight(Ptr<TaskDefinitions.task_struct> p, @Unsigned int weight) {
    }

    /**
     * The CPU affinity mask of a task has changed.
     *
     * @param p       the task whose cpumask changed
     * @param cpumask new allowed-CPU mask
     *
     * <p>Called when a task's CPU affinity is updated (e.g. via
     * {@code sched_setaffinity(2)}).  Schedulers that cache per-CPU placement
     * decisions should invalidate them here.
     *
     * <p>Requires {@code import me.bechberger.ebpf.runtime.runtime.cpumask;}.
     */
    default void setCpumask(Ptr<TaskDefinitions.task_struct> p, Ptr<cpumask> cpumask) {
    }

    /**
     * A task is leaving the scheduler entirely.
     *
     * @param p    the task being removed
     * @param args exit arguments: {@code args.cancelled} is {@code true} when
     *             the task is being removed because {@link #initTask} was called
     *             during load and then cancelled (e.g. the scheduler was
     *             detached before the task's first dispatch).
     *
     * <p>Called once per task, always paired with a prior {@link #initTask}.
     * Use this to free per-task state created in {@link #initTask}.
     * {@link me.bechberger.ebpf.bpf.map.BPFTaskStorage} entries are freed
     * automatically by the kernel, but any other resources must be released here.
     */
    default void exitTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_exit_task_args> args) {
    }

    final int SCHED_EXT_UAPI_ID = 7;

    /**
     * Attach the scheduler's struct_ops to the kernel. Delegates to
     * {@link BPFProgram#attachStructOps()}. Call this after {@code load()}
     * and after any pre-attach configuration (e.g. writing {@code @Property}
     * defaults or setting {@code @GlobalVariable} values that the kernel
     * {@code init} callback needs to observe).
     *
     * <p>Idempotent: safe to call multiple times.
     */
    default void attachScheduler() {
        ((BPFProgram) this).attachStructOps();
    }

    default String getSchedulerName() {
        return ((BPFProgram)this).getPropertyValue("sched_name");
    }

    /**
     * Iterate over all tasks in the DSQ, using the {@code bpf_for_each} macro.
     * <p>
     * This inserts the body of the lambda into the macro,
     * so {@code return} works differently,
     * for {@code break;} use {@link BPFJ#_break()} and for {@code continue;} use {@link BPFJ#_continue()}.
     * Use {@link me.bechberger.ebpf.type.Box} for using non-final variables from outside the lambda.
     * @param dsq_id queue id
     * @param cur current task in the loop
     * @param body lambda to execute for each task
     */
    @BuiltinBPFFunction("""
            bpf_for_each(scx_dsq, $arg2, $arg1, 0) {
                $lambda3:param1:type $lambda3:param1:name = BPF_FOR_EACH_ITER;
                $lambda3:code
            }
            """)
    default void bpf_for_each_dsq(int dsq_id,
                                  Ptr<TaskDefinitions.task_struct> cur,
                                  Consumer<Ptr<BpfDefinitions.bpf_iter_scx_dsq>> body) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Moves task {@code p} from the DSQ iterator position to the local queue of {@code cpu},
     * but only if {@code cpu} is in the task's allowed CPU mask.
     *
     * <p>This is the canonical dispatch helper for schedulers that use
     * {@link #bpf_for_each_dsq} to scan a shared DSQ and dispatch each task to a
     * specific CPU (rather than the caller's local queue).  It corresponds to the
     * pattern used in {@code scx_pair} and other per-CPU-targeted schedulers.
     *
     * <p><b>Note:</b> This method calls {@code bpf_cpumask_test_cpu(cpu, p->cpus_ptr)}, which
     * requires {@code cpus_ptr} to be a BTF-tracked pointer (stack or map value).
     * When {@code p} is an {@code rcu_ptr_task_struct} obtained from a
     * {@link #bpf_for_each_dsq} iterator, the BPF verifier rejects this call with
     * {@code R2 type=scalar expected=fp}. Prefer {@code scx_bpf_dsq_move_to_local}
     * in dispatch, which handles CPU affinity automatically.
     *
     * <p>Returns {@code true} if the task was moved (the caller should stop iterating);
     * {@code false} if the CPU was not in the task's affinity mask.
     *
     * @param iter the DSQ iterator from the {@code bpf_for_each_dsq} lambda parameter
     * @param p    the current task from the iterator
     * @param cpu  target CPU to dispatch to
     */
    @BPFFunction
    @AlwaysInline
    default boolean tryDispatchToLocalCpu(Ptr<BpfDefinitions.bpf_iter_scx_dsq> iter,
                                          Ptr<TaskDefinitions.task_struct> p, int cpu) {
        if (!bpf_cpumask_test_cpu(cpu, p.directVal().cpus_ptr)) {
            return false;
        }
        return scx_bpf_dsq_move(iter, p, SCX_DSQ_LOCAL_ON.value() | cpu, SCX_ENQ_PREEMPT.value());
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
     * Check via /sys/kernel/sched_ext/root/ops whether the scheduler is attached properly.
     */
    default boolean isSchedulerAttachedProperly() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/sys/kernel/sched_ext/root/ops"))) {
            String line = reader.readLine();
            return getSchedulerName().equals(line);
        } catch (IOException e) {
            return false;
        }
    }

    default void waitWhileSchedulerIsAttachedProperly() {
        while (isSchedulerAttachedProperly()) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /**
     * Convenience main-loop: attach the scheduler if not already attached,
     * then block until it detaches (watchdog fire, kernel unload, or
     * SIGINT / SIGTERM), then return.
     *
     * <p>Attach is idempotent — if the caller wrote BPF globals via
     * {@code @GlobalVariable} setters (e.g. {@code prog.configure(...)}) and
     * then invoked {@link #attachScheduler()} explicitly, this method's
     * attach call is a no-op.
     *
     * <p>Typical usage:
     * <pre>{@code
     * public static void main(String[] args) throws Exception {
     *     try (var prog = BPFProgram.load(MyScheduler.class)) {
     *         prog.runSchedulerLoop();
     *     }
     * }
     * }</pre>
     */
    default void runSchedulerLoop() {
        attachScheduler();
        waitWhileSchedulerIsAttachedProperly();
    }

    // -----------------------------------------------------------------------
    // BPF-side convenience helpers (available to ALL Scheduler implementors via
    // the @BPFInterface / @InternalMethodDefinition cross-module mechanism)
    // -----------------------------------------------------------------------

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
     * Selects a CPU using the kernel default; pre-dispatches to
     * {@code SCX_DSQ_LOCAL} when an idle CPU is found.
     *
     * <p><b>Only safe for FIFO DSQs.</b>
     */
    @BPFFunction
    default int selectCpuDefault(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(), 0);
        }
        return cpu;
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
     * @deprecated Renamed to {@link #selectCpuFifoIdleOrFallback} to clarify it is only
     *             safe for FIFO DSQs.  Use {@link #selectCpuDfl} for vtime-ordered DSQs.
     */
    @Deprecated
    @BPFFunction
    default int selectCpuIdleOrFallback(Ptr<task_struct> p, int prev_cpu, long wake_flags,
                                        @Unsigned long dsqId) {
        return selectCpuFifoIdleOrFallback(p, prev_cpu, wake_flags, dsqId);
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
     * Inserts {@code p} into DSQ 0 using vtime-ordered priority.
     *
     * <p>Clamps the task's accumulated vtime so that idle tasks cannot build up
     * more than one {@code SCX_SLICE_DFL} of budget ahead of the global vtime.
     *
     * @param vtimeNow current global virtual time
     * @deprecated Prefer {@link me.bechberger.ebpf.bpf.sched.DispatchQueue#insertVtimeClamped} for new code.
     */
    @Deprecated
    @BPFFunction
    default void vtimeEnqueue(Ptr<task_struct> p, long enq_flags, @Unsigned long vtimeNow) {
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtime, vtimeNow - SCX_SLICE_DFL.value())) {
            vtime = vtimeNow - SCX_SLICE_DFL.value();
        }
        scx_bpf_dsq_insert_vtime(p, 0L, SCX_SLICE_DFL.value(), vtime, enq_flags);
    }

    /**
     * Charges execution time to {@code p}'s virtual time, scaled by the inverse
     * of the task's weight (so heavier tasks advance their vtime more slowly).
     *
     * <p>Call from {@link #stopping(Ptr, boolean)}.
     */
    @BPFFunction
    default void vtimeCharge(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime +=
                (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100 / p.val().scx.weight;
    }

    /**
     * Signals a fatal scheduler error from Java user-space: detaches the scheduler and
     * logs {@code message} to the kernel ring buffer (visible via {@code dmesg}).
     *
     * <p>This is the Java-side companion to the BPF-side {@link #scx_bpf_error(String, Object...)}
     * macro.  It detaches the scheduler (causing an immediate watchdog-style exit) and
     * prints the message through the {@code BPFProgram} error mechanism.
     *
     * @param message human-readable error description (visible in kernel log)
     */
    default void scxError(String message) {
        throw new BPFError("sched_ext scheduler error: " + message);
    }
}