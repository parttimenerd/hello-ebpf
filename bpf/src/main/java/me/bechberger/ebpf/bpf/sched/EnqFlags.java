// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags;

/**
 * Typed wrapper around the {@code enq_flags} bitmask passed to
 * {@code scx_bpf_dsq_insert()} / {@code scx_bpf_dsq_insert_vtime()}.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}): no runtime object
 * is created, every method call is inlined as C, and the carrier is a {@code long} bitmask.
 *
 * <h2>Usage in {@code enqueue()}</h2>
 * <pre>{@code
 * @Override
 * public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *     shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
 * }
 * }</pre>
 *
 * <h2>Composing flags</h2>
 * <pre>{@code
 * EnqFlags f = EnqFlags.of(scx_enq_flags.SCX_ENQ_PREEMPT, scx_enq_flags.SCX_ENQ_HEAD);
 * }</pre>
 */
@BPFAbstraction(constructorPrependTo = "")
public final class EnqFlags {

    /** No flags — empty bitmask. */
    @BuiltinBPFFunction(value = "", carrier = "0")
    @NotUsableInJava
    public static EnqFlags empty() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Wrap the raw {@code enq_flags} parameter received in {@code enqueue()}.
     * This is the correct way to forward flags from the kernel: the raw value
     * may contain kernel-internal bits that must be preserved.
     */
    @BuiltinBPFFunction(value = "", carrier = "$arg1")
    @NotUsableInJava
    public static EnqFlags passThrough(long raw) { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Compose one or more user-visible flags.
     * <pre>{@code
     * EnqFlags.of(scx_enq_flags.SCX_ENQ_PREEMPT)
     * }</pre>
     * Note: only public {@code scx_enq_flags} constants should be passed;
     * do not pass {@code __SCX_ENQ_INTERNAL_MASK} or {@code SCX_ENQ_CLEAR_OPSS}.
     */
    @BuiltinBPFFunction(value = "", carrier = "($arg1)")
    @NotUsableInJava
    public static EnqFlags of(scx_enq_flags flag) { throw new MethodIsBPFRelatedFunction(); }

    /** Combine this set of flags with {@code other}. */
    @BuiltinBPFFunction("($this | $arg1)")
    @NotUsableInJava
    public EnqFlags or(EnqFlags other) { throw new MethodIsBPFRelatedFunction(); }

    /** {@code true} if {@code SCX_ENQ_WAKEUP} is set. */
    @BuiltinBPFFunction("(($this) & SCX_ENQ_WAKEUP)")
    @NotUsableInJava
    public boolean isWakeup() { throw new MethodIsBPFRelatedFunction(); }

    /** {@code true} if {@code SCX_ENQ_REENQ} is set (task is being re-enqueued, e.g. after yield). */
    @BuiltinBPFFunction("(($this) & SCX_ENQ_REENQ)")
    @NotUsableInJava
    public boolean isReenqueued() { throw new MethodIsBPFRelatedFunction(); }

    /** {@code true} if {@code SCX_ENQ_PREEMPT} is set (task is preempting another). */
    @BuiltinBPFFunction("(($this) & SCX_ENQ_PREEMPT)")
    @NotUsableInJava
    public boolean isPreempt() { throw new MethodIsBPFRelatedFunction(); }

    /** {@code true} if {@code SCX_ENQ_LAST} is set (task is last runnable on this CPU). */
    @BuiltinBPFFunction("(($this) & SCX_ENQ_LAST)")
    @NotUsableInJava
    public boolean isLast() { throw new MethodIsBPFRelatedFunction(); }

    /** Unwrap to raw {@code long} — use when calling raw kfuncs directly. */
    @BuiltinBPFFunction("$this")
    @NotUsableInJava
    public @Unsigned long value() { throw new MethodIsBPFRelatedFunction(); }
}
