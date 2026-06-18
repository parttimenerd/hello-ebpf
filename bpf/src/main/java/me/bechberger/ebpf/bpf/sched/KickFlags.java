// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;

/**
 * Typed wrapper for the {@code flags} parameter of {@code scx_bpf_kick_cpu()}.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}): no runtime object
 * is created, every method call is inlined as C, and the carrier is a {@code u32} bitmask.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Wake a CPU only if it is idle:
 * DispatchQueue.kickCpu(cpu, KickFlags.idle());
 *
 * // Preempt whatever is running on cpu:
 * DispatchQueue.kickCpu(cpu, KickFlags.preempt());
 *
 * // Idle + wait for the kicked CPU to finish handling the kick:
 * DispatchQueue.kickCpu(cpu, KickFlags.idle().or(KickFlags.waitForKick()));
 * }</pre>
 */
@BPFAbstraction(constructorPrependTo = "")
public final class KickFlags {

    /** No flags — same as passing {@code 0}. */
    @BuiltinBPFFunction(value = "", carrier = "0")
    @NotUsableInJava
    public static KickFlags none() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Only kick the CPU if it is idle. Most energy-efficient choice; use when
     * you have just enqueued a task and want the idle CPU to wake up and drain.
     */
    @BuiltinBPFFunction(value = "", carrier = "SCX_KICK_IDLE")
    @NotUsableInJava
    public static KickFlags idle() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Preempt whatever task is currently running on the target CPU.
     * Use when a high-priority task must run immediately.
     */
    @BuiltinBPFFunction(value = "", carrier = "SCX_KICK_PREEMPT")
    @NotUsableInJava
    public static KickFlags preempt() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Wait for the kick to be processed before returning.
     * Useful when the caller needs the target CPU's state to have settled
     * (e.g. after {@link #preempt()} to ensure the task has been dequeued).
     * Named {@code waitForKick} to avoid conflict with {@code Object.wait()}.
     */
    @BuiltinBPFFunction(value = "", carrier = "SCX_KICK_WAIT")
    @NotUsableInJava
    public static KickFlags waitForKick() { throw new MethodIsBPFRelatedFunction(); }

    /** Combine this set of flags with {@code other}. */
    @BuiltinBPFFunction("($this | $arg1)")
    @NotUsableInJava
    public KickFlags or(KickFlags other) { throw new MethodIsBPFRelatedFunction(); }

    /** Unwrap to raw {@code int} — use when calling raw kfuncs directly. */
    @BuiltinBPFFunction("$this")
    @NotUsableInJava
    public @Unsigned int value() { throw new MethodIsBPFRelatedFunction(); }
}
