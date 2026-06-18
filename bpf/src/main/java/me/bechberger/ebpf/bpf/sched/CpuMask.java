// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.runtime.cpumask;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Typed wrapper around a read-only {@code const struct cpumask *} pointer.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}) with
 * {@code constructorPrependTo = ""}: no constructor lifting occurs, so a
 * {@code CpuMask} must be constructed inside a {@code @BPFFunction} body rather than
 * as a field initializer on a {@code @BPF} class.
 *
 * <p>The carrier is a {@code const struct cpumask *} obtained from one of the factory
 * methods.  <strong>Always release borrowed masks</strong> with {@link #releaseIdle()} or
 * {@link #release()} when they are no longer needed — failing to do so leaks a reference.
 *
 * <h2>Reference-acquiring factories — use raw kfuncs instead</h2>
 * {@link #idle()}, {@link #idleSmt()}, {@link #idleOnNode}, {@link #online()}, and
 * {@link #possible()} each <em>acquire</em> a kernel reference on every use of the local
 * variable, because the carrier expression is substituted verbatim at each call site.
 * This means calling {@code mask.pickIdle(0)} and then {@code mask.release()} actually
 * calls the factory kfunc <em>twice</em> — acquiring the reference twice while releasing
 * it only once, which the BPF verifier rejects as a reference leak.
 *
 * <p>For any code path that calls both a use-method and a release-method, use the raw
 * kfuncs from {@link me.bechberger.ebpf.runtime.ScxDefinitions} directly:
 * <pre>{@code
 * Ptr<cpumask> possible = scx_bpf_get_possible_cpumask();
 * int cpu = scx_bpf_pick_idle_cpu(possible, 0);
 * scx_bpf_put_cpumask(possible);
 * }</pre>
 *
 * {@link #ofTask(Ptr)} is safe because its carrier ({@code p->cpus_ptr}) is a borrowed
 * pointer with no reference counting — it can be used freely without release.
 *
 * <h2>Read-only constraint</h2>
 * All factories return a <em>read-only</em> {@code const struct cpumask *}.  Operations
 * that require a mutable {@code struct bpf_cpumask *} (e.g. {@code bpf_cpumask_set_cpu},
 * {@code bpf_cpumask_clear_cpu}) are intentionally not exposed here; use the raw
 * {@code bpf_cpumask_*} kfuncs directly.
 *
 * <h2>Usage example</h2>
 * <pre>{@code
 * @Override
 * public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
 *     CpuMask idle = CpuMask.idle();
 *     int cpu = idle.pickIdle(0);
 *     idle.releaseIdle();
 *     if (cpu >= 0) return cpu;
 *     return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(false));
 * }
 * }</pre>
 *
 * <h2>Checking task affinity</h2>
 * <pre>{@code
 * CpuMask allowed = CpuMask.ofTask(p);
 * // no release needed — ofTask() is a read-only view of p->cpus_ptr
 * if (allowed.test(cpu)) { ... }
 * }</pre>
 */
@BPFAbstraction(constructorPrependTo = "")
public final class CpuMask {

    // ── Factories — borrow semantics (release required) ───────────────────────

    /**
     * Borrow the global idle CPU mask. Release with {@link #releaseIdle()} when done.
     * The mask is valid until the next context-switch on any CPU.
     */
    @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_idle_cpumask()")
    @NotUsableInJava
    public static CpuMask idle() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Borrow the idle SMT-sibling mask (only one logical CPU per physical core is
     * marked idle).  Release with {@link #releaseIdle()} when done.
     */
    @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_idle_smtmask()")
    @NotUsableInJava
    public static CpuMask idleSmt() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Borrow the idle CPU mask restricted to NUMA node {@code n}.
     * Release with {@link #releaseIdle()} when done.
     *
     * @param node NUMA node id
     */
    @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_idle_cpumask_node($arg1)")
    @NotUsableInJava
    public static CpuMask idleOnNode(int node) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Borrow the online CPU mask. Release with {@link #release()} when done.
     */
    @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_online_cpumask()")
    @NotUsableInJava
    public static CpuMask online() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Borrow the possible CPU mask. Release with {@link #release()} when done.
     */
    @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_possible_cpumask()")
    @NotUsableInJava
    public static CpuMask possible() { throw new MethodIsBPFRelatedFunction(); }

    // ── Factories — no release needed ────────────────────────────────────────

    /**
     * Read-only view of {@code p->cpus_ptr} (the task's CPU affinity mask).
     * No release is needed — this is a direct pointer into the task structure.
     *
     * <pre>{@code
     * CpuMask allowed = CpuMask.ofTask(p);
     * if (allowed.test(cpu)) { ... }
     * }</pre>
     *
     * @param p task whose affinity to read
     */
    @BuiltinBPFFunction(value = "", carrier = "($arg1->cpus_ptr)")
    @NotUsableInJava
    public static CpuMask ofTask(Ptr<task_struct> p) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Wrap an arbitrary {@code const struct cpumask *} pointer.
     * Release policy depends on how the pointer was obtained.
     *
     * @param ptr pointer to an existing cpumask
     */
    @BuiltinBPFFunction(value = "", carrier = "$arg1")
    @NotUsableInJava
    public static CpuMask of(Ptr<cpumask> ptr) { throw new MethodIsBPFRelatedFunction(); }

    // ── Release ───────────────────────────────────────────────────────────────

    /**
     * Release this mask.  Use for masks obtained via {@link #idle()},
     * {@link #idleSmt()}, or {@link #idleOnNode(int)}.
     */
    @BuiltinBPFFunction("scx_bpf_put_idle_cpumask((const struct cpumask*)$this)")
    @NotUsableInJava
    public void releaseIdle() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Release this mask.  Use for masks obtained via {@link #online()} or
     * {@link #possible()}.
     */
    @BuiltinBPFFunction("scx_bpf_put_cpumask((const struct cpumask*)$this)")
    @NotUsableInJava
    public void release() { throw new MethodIsBPFRelatedFunction(); }

    // ── Read operations ───────────────────────────────────────────────────────

    /**
     * Returns {@code true} if {@code cpu} is set in this mask.
     *
     * @param cpu CPU number to test
     */
    @BuiltinBPFFunction("bpf_cpumask_test_cpu($arg1, $this)")
    @NotUsableInJava
    public boolean test(int cpu) { throw new MethodIsBPFRelatedFunction(); }

    /** Number of CPUs set in this mask. */
    @BuiltinBPFFunction("bpf_cpumask_weight($this)")
    @NotUsableInJava
    public @Unsigned int weight() { throw new MethodIsBPFRelatedFunction(); }

    /** Lowest-numbered CPU set in this mask, or {@code >= nr_cpu_ids} if empty. */
    @BuiltinBPFFunction("bpf_cpumask_first($this)")
    @NotUsableInJava
    public @Unsigned int first() { throw new MethodIsBPFRelatedFunction(); }

    /** Lowest-numbered CPU <em>not</em> set in this mask, or {@code >= nr_cpu_ids} if full. */
    @BuiltinBPFFunction("bpf_cpumask_first_zero($this)")
    @NotUsableInJava
    public @Unsigned int firstZero() { throw new MethodIsBPFRelatedFunction(); }

    /** {@code true} if no CPUs are set in this mask. */
    @BuiltinBPFFunction("bpf_cpumask_empty($this)")
    @NotUsableInJava
    public boolean isEmpty() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * {@code true} if {@code this} and {@code other} have at least one CPU in common.
     *
     * @param other second mask to intersect with
     */
    @BuiltinBPFFunction("bpf_cpumask_intersects($this, $arg1)")
    @NotUsableInJava
    public boolean intersects(CpuMask other) { throw new MethodIsBPFRelatedFunction(); }

    // ── Idle CPU selection ────────────────────────────────────────────────────

    /**
     * Pick and claim an idle CPU from this mask.
     * Returns a non-negative CPU number on success, or {@code -EBUSY} if none is idle.
     *
     * @param flags reserved; pass {@code 0}
     */
    @BuiltinBPFFunction("scx_bpf_pick_idle_cpu((const struct cpumask*)$this, $arg1)")
    @NotUsableInJava
    public int pickIdle(@Unsigned long flags) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Pick any CPU from this mask, preferring idle ones.
     * Returns a non-negative CPU number, or negative on error.
     *
     * @param flags reserved; pass {@code 0}
     */
    @BuiltinBPFFunction("scx_bpf_pick_any_cpu((const struct cpumask*)$this, $arg1)")
    @NotUsableInJava
    public int pickAny(@Unsigned long flags) { throw new MethodIsBPFRelatedFunction(); }
}
