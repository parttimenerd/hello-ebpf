// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import java.util.function.Consumer;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_iter_scx_dsq;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Typed wrapper around a sched_ext Dispatch-Queue (DSQ) id.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}):
 * the carrier is the {@code u64} DSQ id stored in the {@link #id} field; no struct is
 * emitted in C, and every {@link BPFJavaInline} method call is inlined by the BPF
 * compiler plugin at the call site.  When a {@code DispatchQueue} field is declared on a
 * {@code @BPF} program class the constructor's {@code scx_bpf_create_dsq()} call is
 * automatically lifted into {@code init()} in source-declaration order.
 *
 * <h2>Creating and using a custom DSQ</h2>
 * <pre>{@code
 * @BPF
 * abstract class MyScheduler extends SchedulerBase implements Scheduler {
 *
 *     // Lifted to init(): scx_bpf_create_dsq(NORMAL_DSQ, -1)
 *     final DispatchQueue normal = new DispatchQueue(NORMAL_DSQ);
 *
 *     @Override public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         normal.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
 *     }
 *
 *     @Override public void dispatch(int cpu, Ptr<task_struct> prev) {
 *         normal.moveToLocal();
 *     }
 * }
 * }</pre>
 *
 * <h2>Attaching to an already-existing DSQ</h2>
 * Use {@link #attach(long)} when the DSQ is created by {@code SchedulerBase.init()} or
 * another part of the initialiser — no {@code scx_bpf_create_dsq} is emitted:
 * <pre>{@code
 * final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);
 * }</pre>
 *
 * <h2>Auto-id allocation</h2>
 * Use {@link #DispatchQueue()} or {@link #DispatchQueue(int)} when you don't care about
 * the numeric id — the annotation processor mints a unique id ≥ {@code 0x1_0000_0000}
 * per program class (in source-declaration order) so it never collides with user ids.
 *
 * <h2>Mode safety</h2>
 * FIFO ({@link #insert}) and vtime ({@link #insertVtime}) operations must <em>not</em>
 * be mixed on the same DSQ.  Use a dedicated DSQ for each mode.
 *
 * <h2>init() override requirement</h2>
 * The {@code scx_bpf_create_dsq()} prologue is injected into the <em>declared</em>
 * {@code init()} on the concrete {@code @BPF} class.  If you extend {@link
 * me.bechberger.ebpf.bpf.SchedulerBase} the inherited {@code init()} already qualifies.
 * If you extend {@link me.bechberger.ebpf.bpf.BPFProgram} directly you <strong>must</strong>
 * declare an explicit {@code init()} override — otherwise no prologue is injected and the
 * DSQ is never created, causing the scheduler to detach immediately:
 * <pre>{@code
 * final DispatchQueue shared = new DispatchQueue(SHARED_DSQ_ID);
 *
 * @Override
 * public int init() {
 *     // scx_bpf_create_dsq(SHARED_DSQ_ID, -1) is injected here by the compiler plugin.
 *     return 0;
 * }
 * }</pre>
 * <h2>Java method bodies ({@link BPFJavaInline})</h2>
 * All instance methods are written as plain Java and inlined at call sites by the BPF
 * compiler plugin.  The {@link #id} field resolves to the caller's carrier expression
 * (the DSQ id) — no C template string is required.
 */
@BPFAbstraction(constructorPrependTo = "init")
public final class DispatchQueue {

    /**
     * The DSQ id carrier.  Inside {@link BPFJavaInline} method bodies, references to
     * {@code id} are replaced by the actual DSQ id expression at each call site.
     * Not accessible from Java runtime code.
     */
    @NotUsableInJava
    private final @Unsigned long id = 0;

    // ── Construction ──────────────────────────────────────────────────────────

    /**
     * Auto-id, NUMA node {@code -1} (any node).
     * The annotation processor mints a fresh id ≥ {@code 0x1_0000_0000} per program
     * class (in source-declaration order) so it never collides with user-chosen ids.
     * {@code scx_bpf_create_dsq(<auto>, -1)} is lifted into {@code init()}.
     */
    @BuiltinBPFFunction(value = "scx_bpf_create_dsq(<auto>, -1)", carrier = "<auto>")
    @NotUsableInJava
    public DispatchQueue() {}

    /**
     * Auto-id, explicit NUMA node.
     * {@code scx_bpf_create_dsq(<auto>, $arg1)} is lifted into {@code init()}.
     *
     * @param node NUMA node id, or {@code -1} for any node
     */
    @BuiltinBPFFunction(value = "scx_bpf_create_dsq(<auto>, $arg1)", carrier = "<auto>")
    @NotUsableInJava
    public DispatchQueue(int node) {}

    /**
     * Explicit id, NUMA node {@code -1} (any node).
     * {@code scx_bpf_create_dsq($arg1, -1)} is lifted into {@code init()}.
     *
     * @param id custom DSQ id; must be unique per program
     */
    @BuiltinBPFFunction(value = "scx_bpf_create_dsq($arg1, -1)", carrier = "$arg1")
    @NotUsableInJava
    public DispatchQueue(@Unsigned long id) {}

    /**
     * Explicit id and NUMA node.
     * {@code scx_bpf_create_dsq($arg1, $arg2)} is lifted into {@code init()}.
     *
     * @param id   custom DSQ id; must be unique per program
     * @param node NUMA node id, or {@code -1} for any node
     */
    @BuiltinBPFFunction(value = "scx_bpf_create_dsq($arg1, $arg2)", carrier = "$arg1")
    @NotUsableInJava
    public DispatchQueue(@Unsigned long id, int node) {}

    /**
     * Wrap an <em>already-existing</em> DSQ id — no {@code scx_bpf_create_dsq} is emitted.
     * Use for DSQs created by {@code SchedulerBase.init()} or a peer class.
     *
     * <pre>{@code
     * // SchedulerBase.init() already created SHARED_DSQ_ID — just attach:
     * final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);
     * }</pre>
     */
    @BuiltinBPFFunction(value = "", carrier = "$arg1")
    @NotUsableInJava
    public static DispatchQueue attach(@Unsigned long id) { return null; }

    // ── Built-in DSQs (no create needed) ─────────────────────────────────────

    /** {@code SCX_DSQ_LOCAL} — the current CPU's local run queue. */
    @BuiltinBPFFunction(value = "", carrier = "SCX_DSQ_LOCAL")
    @NotUsableInJava
    public static DispatchQueue local() { return null; }

    /**
     * {@code SCX_DSQ_LOCAL_ON | cpu} — local run queue of a specific CPU.
     * @param cpu target CPU number
     */
    @BuiltinBPFFunction(value = "", carrier = "(SCX_DSQ_LOCAL_ON | (u64)$arg1)")
    @NotUsableInJava
    public static DispatchQueue localOn(int cpu) { return null; }

    /** {@code SCX_DSQ_GLOBAL} — the kernel's global FIFO run queue. */
    @BuiltinBPFFunction(value = "", carrier = "SCX_DSQ_GLOBAL")
    @NotUsableInJava
    public static DispatchQueue global() { return null; }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * Destroy this DSQ.  Custom DSQs are auto-cleaned on scheduler detach; call this
     * only when you need explicit cleanup (e.g. from {@code exit()}).
     */
    @BuiltinBPFFunction("scx_bpf_destroy_dsq($this)")
    @NotUsableInJava
    public void destroy() { throw new MethodIsBPFRelatedFunction(); }

    // ── FIFO insertion ────────────────────────────────────────────────────────

    /**
     * FIFO-insert {@code p} into this DSQ with an explicit time slice.
     * <b>Never mix with {@link #insertVtime} on the same DSQ.</b>
     *
     * @param p     task to insert
     * @param slice budget in nanoseconds; {@code -1} means no preemption
     * @param flags pass {@link EnqFlags#passThrough(long)} from {@code enqueue()}
     */
    @BuiltinBPFFunction("scx_bpf_dsq_insert($arg1, $this, $arg2, $arg3)")
    @NotUsableInJava
    public void insert(Ptr<task_struct> p, long slice, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * FIFO-insert with a slice scaled inversely to the current queue depth.
     * Tasks arriving at a heavily-loaded DSQ get a proportionally shorter slice.
     * When the queue is empty {@code SCX_SLICE_DFL} is used.
     *
     * @param p     task to insert
     * @param flags pass {@link EnqFlags#passThrough(long)} from {@code enqueue()}
     */
    @BuiltinBPFFunction("scx_bpf_dsq_insert($arg1, $this, " +
        "scx_bpf_dsq_nr_queued($this) > 0 " +
        "  ? SCX_SLICE_DFL / scx_bpf_dsq_nr_queued($this) " +
        "  : SCX_SLICE_DFL, " +
        "$arg2)")
    @NotUsableInJava
    public void insertScaled(Ptr<task_struct> p, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Fast-path from {@code selectCPU()}: when {@code isIdle} is {@code true}, inserts
     * {@code p} directly into {@code SCX_DSQ_LOCAL} with {@code slice}.
     *
     * @param p      task to insert
     * @param isIdle result from {@code scx_bpf_select_cpu_dfl}
     * @param slice  budget in nanoseconds
     */
    @BuiltinBPFFunction("if ($arg2) scx_bpf_dsq_insert($arg1, SCX_DSQ_LOCAL, $arg3, 0)")
    @NotUsableInJava
    public static void insertToLocalIfIdle(Ptr<task_struct> p, boolean isIdle, long slice) { throw new MethodIsBPFRelatedFunction(); }

    // ── Vtime insertion ───────────────────────────────────────────────────────

    /**
     * Vtime-ordered insert: the task with the smallest {@code vtime} runs first.
     * <b>Never mix with {@link #insert} on the same DSQ.</b>
     *
     * @param p     task to insert
     * @param slice budget in nanoseconds
     * @param vtime virtual time; smaller = higher priority
     * @param flags pass {@link EnqFlags#passThrough(long)} from {@code enqueue()}
     */
    @BuiltinBPFFunction("scx_bpf_dsq_insert_vtime($arg1, $this, $arg2, $arg3, $arg4)")
    @NotUsableInJava
    public void insertVtime(Ptr<task_struct> p, long slice, @Unsigned long vtime, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Vtime-insert with idle-budget clamping: caps {@code p->scx.dsq_vtime} so that a
     * long-sleeping task cannot accumulate more than one {@code SCX_SLICE_DFL} of credit
     * ahead of {@code vtimeNow}.
     *
     * @param p        task to insert
     * @param vtimeNow current global virtual time
     * @param flags    pass {@link EnqFlags#passThrough(long)} from {@code enqueue()}
     */
    @BuiltinBPFFunction("({ u64 __v = $arg1->scx.dsq_vtime; " +
        "if ((s64)(__v - ($arg2 - SCX_SLICE_DFL)) < 0) __v = $arg2 - SCX_SLICE_DFL; " +
        "scx_bpf_dsq_insert_vtime($arg1, $this, SCX_SLICE_DFL, __v, $arg3); })")
    @NotUsableInJava
    public void insertVtimeClamped(Ptr<task_struct> p, @Unsigned long vtimeNow, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    // ── Consumption / movement ────────────────────────────────────────────────

    /**
     * Move one task from this DSQ to the current CPU's local run queue.
     * Returns {@code true} if a task was moved.  Call from {@code dispatch()}.
     */
    @BuiltinBPFFunction("scx_bpf_dsq_move_to_local($this)")
    @NotUsableInJava
    public boolean moveToLocal() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Inside a {@link #forEach} body: move the task {@code p} into this DSQ (FIFO).
     *
     * @param it    the current DSQ iterator
     * @param p     the task to move
     * @param flags enqueue flags for the destination
     * @return {@code true} on success
     */
    @BuiltinBPFFunction("scx_bpf_dsq_move($arg1, $arg2, $this, $arg3)")
    @NotUsableInJava
    public boolean moveFrom(Ptr<bpf_iter_scx_dsq> it, Ptr<task_struct> p, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Vtime variant of {@link #moveFrom}.
     *
     * @param it    the current DSQ iterator
     * @param p     the task to move
     * @param flags enqueue flags for the destination
     * @return {@code true} on success
     */
    @BuiltinBPFFunction("scx_bpf_dsq_move_vtime($arg1, $arg2, $this, $arg3)")
    @NotUsableInJava
    public boolean moveFromVtime(Ptr<bpf_iter_scx_dsq> it, Ptr<task_struct> p, EnqFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Override the slice assigned by the next {@link #moveFrom} call.
     * Must be called immediately before {@link #moveFrom}.
     */
    @BuiltinBPFFunction("scx_bpf_dsq_move_set_slice($arg1, $arg2)")
    @NotUsableInJava
    public static void setMoveSlice(Ptr<bpf_iter_scx_dsq> it, long slice) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Override the vtime assigned by the next {@link #moveFromVtime} call.
     * Must be called immediately before {@link #moveFromVtime}.
     */
    @BuiltinBPFFunction("scx_bpf_dsq_move_set_vtime($arg1, $arg2)")
    @NotUsableInJava
    public static void setMoveVtime(Ptr<bpf_iter_scx_dsq> it, @Unsigned long vtime) { throw new MethodIsBPFRelatedFunction(); }

    // ── Inspection ────────────────────────────────────────────────────────────

    /** Number of tasks currently enqueued in this DSQ. */
    @BuiltinBPFFunction("scx_bpf_dsq_nr_queued($this)")
    @NotUsableInJava
    public @Unsigned int nrQueued() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * {@code true} when {@link #nrQueued()} {@code > 0}.
     * <pre>{@code
     * if (boosted.nonEmpty()) boosted.moveToLocal();
     * else                    normal.moveToLocal();
     * }</pre>
     */
    @BuiltinBPFFunction("(scx_bpf_dsq_nr_queued($this) > 0)")
    @NotUsableInJava
    public boolean nonEmpty() { throw new MethodIsBPFRelatedFunction(); }

    // ── Iteration ─────────────────────────────────────────────────────────────

    /**
     * Forward iteration over every task in this DSQ.
     * {@link me.bechberger.ebpf.bpf.BPFJ#_break()} and
     * {@link me.bechberger.ebpf.bpf.BPFJ#_continue()} work inside the lambda.
     *
     * <pre>{@code
     * shared.forEach(it, p -> {
     *     if (!bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)) return;
     *     shared.moveFrom(it, p, EnqFlags.empty());
     *     BPFJ._break();
     * });
     * }</pre>
     */
    @BuiltinBPFFunction("bpf_for_each(scx_dsq, $arg1, $this, 0) {\n    $lambda2:body\n}")
    @NotUsableInJava
    public void forEach(Ptr<bpf_iter_scx_dsq> it, Consumer<Ptr<task_struct>> body) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Reverse-order iteration (flag {@code SCX_DSQ_ITER_REV}).
     */
    @BuiltinBPFFunction("bpf_for_each(scx_dsq, $arg1, $this, SCX_DSQ_ITER_REV) {\n    $lambda2:body\n}")
    @NotUsableInJava
    public void forEachReverse(Ptr<bpf_iter_scx_dsq> it, Consumer<Ptr<task_struct>> body) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Open a manual DSQ iterator. Always close with {@link #iteratorDestroy}.
     *
     * @param it    iterator to initialise
     * @param flags {@code 0} = forward; {@code SCX_DSQ_ITER_REV} = reverse
     * @return 0 on success
     */
    @BuiltinBPFFunction("bpf_iter_scx_dsq_new($arg1, $this, $arg2)")
    @NotUsableInJava
    public int iteratorNew(Ptr<bpf_iter_scx_dsq> it, int flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Advance a manual iterator.
     *
     * @param it the iterator
     * @return next task or {@code null} when exhausted
     */
    @BuiltinBPFFunction("bpf_iter_scx_dsq_next($arg1)")
    @NotUsableInJava
    public static Ptr<task_struct> iteratorNext(Ptr<bpf_iter_scx_dsq> it) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Close a manual iterator.  Must be called even on early exit.
     */
    @BuiltinBPFFunction("bpf_iter_scx_dsq_destroy($arg1)")
    @NotUsableInJava
    public static void iteratorDestroy(Ptr<bpf_iter_scx_dsq> it) { throw new MethodIsBPFRelatedFunction(); }

    // ── Dispatch-time control ─────────────────────────────────────────────────

    /** Cancel the pending dispatch batch. */
    @BuiltinBPFFunction("scx_bpf_dispatch_cancel()")
    @NotUsableInJava
    public static void cancelDispatch() { throw new MethodIsBPFRelatedFunction(); }

    /** Slots remaining in the current dispatch batch. */
    @BuiltinBPFFunction("scx_bpf_dispatch_nr_slots()")
    @NotUsableInJava
    public static @Unsigned int dispatchNrSlots() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Re-enqueue all tasks pinned to local DSQs.  Call from {@code cpuRelease()}.
     */
    @BuiltinBPFFunction("scx_bpf_reenqueue_local()")
    @NotUsableInJava
    public static @Unsigned int reenqueueLocal() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Wake remote {@code cpu} to trigger dispatch.
     *
     * @param cpu   target CPU
     * @param flags use {@link KickFlags#idle()}, {@link KickFlags#preempt()}, or {@link KickFlags#waitForKick()}
     */
    @BuiltinBPFFunction("scx_bpf_kick_cpu($arg1, $arg2)")
    @NotUsableInJava
    public static void kickCpu(int cpu, KickFlags flags) { throw new MethodIsBPFRelatedFunction(); }

    // ── Slice manipulation ────────────────────────────────────────────────────

    /**
     * Extend the running task's remaining slice by {@code ns}.
     */
    @BuiltinBPFFunction("$arg1->scx.slice += $arg2")
    @NotUsableInJava
    public static void extendSlice(Ptr<task_struct> p, long ns) { throw new MethodIsBPFRelatedFunction(); }

    /** Zero the running task's slice, forcing an immediate reschedule. */
    @BuiltinBPFFunction("$arg1->scx.slice = 0")
    @NotUsableInJava
    public static void yieldNow(Ptr<task_struct> p) { throw new MethodIsBPFRelatedFunction(); }

    // ── Timing ───────────────────────────────────────────────────────────────

    /**
     * Current monotonic timestamp in nanoseconds ({@code scx_bpf_now()}).
     */
    @BuiltinBPFFunction("scx_bpf_now()")
    @NotUsableInJava
    public static @Unsigned long now() { throw new MethodIsBPFRelatedFunction(); }

    // ── CPU topology helpers ──────────────────────────────────────────────────

    /** Number of possible CPU ids. */
    @BuiltinBPFFunction("scx_bpf_nr_cpu_ids()")
    @NotUsableInJava
    public static @Unsigned int nrCpuIds() { throw new MethodIsBPFRelatedFunction(); }

    /** Number of NUMA nodes. */
    @BuiltinBPFFunction("scx_bpf_nr_node_ids()")
    @NotUsableInJava
    public static @Unsigned int nrNodeIds() { throw new MethodIsBPFRelatedFunction(); }

    /** NUMA node of {@code cpu}. Returns {@code -EINVAL} for invalid CPU. */
    @BuiltinBPFFunction("scx_bpf_cpu_node($arg1)")
    @NotUsableInJava
    public static int cpuNode(int cpu) { throw new MethodIsBPFRelatedFunction(); }

    // ── CPU idle helpers ──────────────────────────────────────────────────────

    /**
     * Atomically test-and-clear the idle flag of {@code cpu}.
     * Returns {@code true} if the CPU was idle (and is now claimed).
     */
    @BuiltinBPFFunction("scx_bpf_test_and_clear_cpu_idle($arg1)")
    @NotUsableInJava
    public static boolean testAndClearCpuIdle(int cpu) { throw new MethodIsBPFRelatedFunction(); }

    // ── CPU performance scaling ───────────────────────────────────────────────

    /** Maximum performance level of {@code cpu} (0–1024). */
    @BuiltinBPFFunction("scx_bpf_cpuperf_cap($arg1)")
    @NotUsableInJava
    public static @Unsigned int cpuperfCap(int cpu) { throw new MethodIsBPFRelatedFunction(); }

    /** Current requested performance level of {@code cpu} (0–1024). */
    @BuiltinBPFFunction("scx_bpf_cpuperf_cur($arg1)")
    @NotUsableInJava
    public static @Unsigned int cpuperfCur(int cpu) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Request that {@code cpu} run at performance level {@code perf} (0–1024).
     */
    @BuiltinBPFFunction("scx_bpf_cpuperf_set($arg1, $arg2)")
    @NotUsableInJava
    public static void cpuperfSet(int cpu, @Unsigned int perf) { throw new MethodIsBPFRelatedFunction(); }
}
