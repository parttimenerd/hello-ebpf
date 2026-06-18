// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.perf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.map.BPFStackTraceMap;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_data;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_perf_event_value;
import static me.bechberger.ebpf.runtime.PtDefinitions.pt_regs;

/**
 * Typed wrapper around {@code struct bpf_perf_event_data *ctx} —
 * the context pointer received by every {@code SEC("perf_event")} BPF program.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}): no runtime object
 * is created; every method call is inlined as C via its {@link BuiltinBPFFunction} template.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * @BPFFunction(section = "perf_event",
 *              headerTemplate = "int BPF_PROG(onSample, struct bpf_perf_event_data *ctx)",
 *              lastStatement = "return 0")
 * public void onSample(Ptr<bpf_perf_event_data> ctx) {
 *     PerfEvent pe = PerfEvent.of(ctx);
 *     long ustackId = pe.getStackId(stackTraces, PerfEvent.STACK_USER | PerfEvent.STACK_REUSE);
 *     long kstackId = pe.getStackId(stackTraces, PerfEvent.STACK_REUSE);
 *     long period   = pe.samplePeriod();
 * }
 * }</pre>
 */
@BPFAbstraction(constructorPrependTo = "")
public final class PerfEvent {

    // ── Stack flags ───────────────────────────────────────────────────────────

    /** Collect user-space stack ({@code BPF_F_USER_STACK}). */
    public static final long STACK_USER = 1L << 8;

    /** Reuse existing entry on hash collision ({@code BPF_F_REUSE_STACKID}). */
    public static final long STACK_REUSE = 1L << 10;

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Wrap the raw {@code bpf_perf_event_data} context pointer received by a
     * {@code SEC("perf_event")} handler.
     *
     * @param ctx the context pointer passed to the BPF program entry point
     */
    @BuiltinBPFFunction(value = "", carrier = "$arg1")
    @NotUsableInJava
    public static PerfEvent of(Ptr<bpf_perf_event_data> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }

    // ── Context fields ────────────────────────────────────────────────────────

    /**
     * Current sampling period in events (may be randomized by the kernel for
     * frequency-based perf events).
     */
    @BuiltinBPFFunction("$this->sample_period")
    @NotUsableInJava
    public @Unsigned long samplePeriod() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Address associated with the sample.  Non-zero only for memory-access
     * ({@code PERF_SAMPLE_ADDR}) events; zero for plain CPU-cycle samples.
     */
    @BuiltinBPFFunction("$this->addr")
    @NotUsableInJava
    public @Unsigned long addr() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Pointer to the CPU register context captured at the sample point.
     * Use with {@code bpf_probe_read_kernel} or {@code PT_REGS_*} macros.
     */
    @BuiltinBPFFunction("(&$this->regs)")
    @NotUsableInJava
    public Ptr<pt_regs> regs() { throw new MethodIsBPFRelatedFunction(); }

    // ── Stack capture ─────────────────────────────────────────────────────────

    /**
     * Record the current call stack in {@code map} and return its integer ID.
     *
     * <p>Pass {@link #STACK_USER} to capture the user-space call stack; omit it
     * (or pass {@code 0}) for the kernel stack.  Add {@link #STACK_REUSE} to
     * avoid {@code -EEXIST} when the slot is already occupied.
     *
     * @param map   a {@link BPFStackTraceMap} declared on the same program class
     * @param flags combination of {@link #STACK_USER}, {@link #STACK_REUSE}, etc.
     * @return non-negative stack ID on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_get_stackid($this, &$arg1, $arg2)")
    @NotUsableInJava
    public long getStackId(BPFStackTraceMap map, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Copy at most {@code size} bytes of instruction-pointer addresses into {@code buf}.
     *
     * <p>Pass {@link #STACK_USER} to capture user-space frames; {@code 0} for kernel frames.
     * Each frame occupies 8 bytes (one {@code u64}).
     *
     * @param buf   destination buffer (e.g. a fixed-size array field)
     * @param size  byte size of {@code buf}
     * @param flags {@link #STACK_USER} or {@code 0}
     * @return bytes copied (non-negative) on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_get_stack($this, $arg1, $arg2, $arg3)")
    @NotUsableInJava
    public long getStack(Ptr<?> buf, @Unsigned int size, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }

    // ── Counter reading ───────────────────────────────────────────────────────

    /**
     * Read the current perf-event counter into {@code buf}.
     *
     * <p>Fills {@code buf.counter} (raw count), {@code buf.enabled} (nanoseconds the
     * event was enabled), and {@code buf.running} (nanoseconds the event was on the PMU).
     *
     * @param buf caller-allocated {@link bpf_perf_event_value} struct
     * @return 0 on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_perf_prog_read_value($this, $arg1, sizeof(*$arg1))")
    @NotUsableInJava
    public long readValue(Ptr<bpf_perf_event_value> buf) {
        throw new MethodIsBPFRelatedFunction();
    }
}
