// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.probe;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFAbstraction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.PtDefinitions.pt_regs;

/**
 * Typed wrapper around {@code struct pt_regs *ctx} — the register context
 * received by {@code SEC("kprobe/...")}, {@code SEC("kretprobe/...")},
 * {@code SEC("fentry/...")}, and {@code SEC("fexit/...")} BPF programs.
 *
 * <p>This is a pure compile-time abstraction ({@link BPFAbstraction}): no runtime
 * object is created; every method call is inlined as C via its {@link BuiltinBPFFunction}
 * template.  The carrier is the raw {@code struct pt_regs *} context pointer.
 *
 * <p>Argument accessors ({@link #arg0()} through {@link #arg5()}) use the standard
 * {@code PT_REGS_PARM1}–{@code PT_REGS_PARM6} macros from {@code bpf_tracing.h},
 * which resolve to the correct general-purpose registers for the host architecture
 * (x86-64, ARM64, etc.) at BPF compile time.
 *
 * <h2>Kprobe usage</h2>
 * <pre>{@code
 * @BPF(license = "GPL")
 * abstract class MyTracer extends BPFProgram {
 *
 *     @BPFFunction(section = "kprobe/do_sys_openat2",
 *                  headerTemplate = "int $name(struct pt_regs *ctx)",
 *                  lastStatement = "return 0")
 *     public void onOpenat2(Ptr<pt_regs> ctx) {
 *         ProbeContext pc = ProbeContext.of(ctx);
 *         long fd = pc.arg0();   // first argument of do_sys_openat2
 *         long ret = pc.retval(); // (in kretprobe) return value
 *     }
 * }
 * }</pre>
 *
 * <h2>Architecture note</h2>
 * {@link #arg0()} through {@link #arg5()} expand to {@code PT_REGS_PARM1(ctx)} through
 * {@code PT_REGS_PARM6(ctx)}.  {@link #retval()} expands to {@code PT_REGS_RC(ctx)}.
 * These macros are defined in {@code bpf_tracing.h} and automatically select the right
 * registers for x86-64, arm64, s390, riscv, etc.  Direct field access (e.g.
 * {@link #ip()}, {@link #sp()}) uses architecture-neutral names from the Linux
 * {@code struct pt_regs} ABI.
 */
@BPFAbstraction(constructorPrependTo = "")
public final class ProbeContext {

    // ── Factory ───────────────────────────────────────────────────────────────

    /**
     * Wrap the raw {@code pt_regs} context pointer received by a kprobe, kretprobe,
     * fentry, or fexit handler.
     *
     * @param ctx the {@code struct pt_regs *ctx} passed to the BPF program entry point
     */
    @BuiltinBPFFunction(value = "", carrier = "$arg1")
    @NotUsableInJava
    public static ProbeContext of(Ptr<pt_regs> ctx) {
        throw new MethodIsBPFRelatedFunction();
    }

    // ── Function argument accessors (architecture-portable) ──────────────────

    /**
     * First function argument (uses {@code PT_REGS_PARM1} macro).
     * On x86-64 this is the {@code rdi} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM1($this)")
    @NotUsableInJava
    public @Unsigned long arg0() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Second function argument (uses {@code PT_REGS_PARM2} macro).
     * On x86-64 this is the {@code rsi} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM2($this)")
    @NotUsableInJava
    public @Unsigned long arg1() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Third function argument (uses {@code PT_REGS_PARM3} macro).
     * On x86-64 this is the {@code rdx} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM3($this)")
    @NotUsableInJava
    public @Unsigned long arg2() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Fourth function argument (uses {@code PT_REGS_PARM4} macro).
     * On x86-64 this is the {@code rcx} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM4($this)")
    @NotUsableInJava
    public @Unsigned long arg3() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Fifth function argument (uses {@code PT_REGS_PARM5} macro).
     * On x86-64 this is the {@code r8} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM5($this)")
    @NotUsableInJava
    public @Unsigned long arg4() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Sixth function argument (uses {@code PT_REGS_PARM6} macro).
     * On x86-64 this is the {@code r9} register.
     */
    @BuiltinBPFFunction("PT_REGS_PARM6($this)")
    @NotUsableInJava
    public @Unsigned long arg5() { throw new MethodIsBPFRelatedFunction(); }

    // ── Return-value accessor (kretprobe / fexit) ─────────────────────────────

    /**
     * Function return value (uses {@code PT_REGS_RC} macro).
     * Valid only in {@code SEC("kretprobe/...")} or {@code SEC("fexit/...")} handlers.
     * On x86-64 this is the {@code rax} register.
     */
    @BuiltinBPFFunction("PT_REGS_RC($this)")
    @NotUsableInJava
    public @Unsigned long retval() { throw new MethodIsBPFRelatedFunction(); }

    // ── Program counter / stack pointer ──────────────────────────────────────

    /**
     * Instruction pointer at the probe site (uses {@code PT_REGS_IP} macro).
     */
    @BuiltinBPFFunction("PT_REGS_IP($this)")
    @NotUsableInJava
    public @Unsigned long ip() { throw new MethodIsBPFRelatedFunction(); }

    /**
     * Stack pointer at the probe site (uses {@code PT_REGS_SP} macro).
     */
    @BuiltinBPFFunction("PT_REGS_SP($this)")
    @NotUsableInJava
    public @Unsigned long sp() { throw new MethodIsBPFRelatedFunction(); }

    // ── Raw context ───────────────────────────────────────────────────────────

    /**
     * Raw pointer to the underlying {@code struct pt_regs}.
     * Use when a helper requires the context pointer directly
     * (e.g. {@code bpf_get_stack}, {@code bpf_perf_event_output}).
     */
    @BuiltinBPFFunction("$this")
    @NotUsableInJava
    public Ptr<pt_regs> regs() { throw new MethodIsBPFRelatedFunction(); }

    // ── Safe kernel-memory read ────────────────────────────────────────────────

    /**
     * Safely read {@code size} bytes from kernel address {@code src} into {@code dst}.
     * Wraps {@code bpf_probe_read_kernel}.
     *
     * @param dst  destination buffer
     * @param size number of bytes to read
     * @param src  source kernel pointer
     * @return 0 on success; negative errno on failure (e.g. invalid address)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel($arg1, $arg2, (const void*)$arg3)")
    @NotUsableInJava
    public static long probeRead(Ptr<?> dst, @Unsigned int size, Ptr<?> src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Safely read a NUL-terminated string from kernel address {@code src} into {@code dst}.
     * Wraps {@code bpf_probe_read_kernel_str}.
     *
     * @param dst     destination buffer
     * @param size    maximum bytes to copy (including NUL terminator)
     * @param src     source kernel string pointer
     * @return length of the string (including NUL) on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, $arg2, (const void*)$arg3)")
    @NotUsableInJava
    public static long probeReadStr(Ptr<?> dst, @Unsigned int size, Ptr<?> src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Safely read {@code size} bytes from user-space address {@code src} into {@code dst}.
     * Wraps {@code bpf_probe_read_user}.
     *
     * @param dst  destination buffer
     * @param size number of bytes to read
     * @param src  source user-space pointer
     * @return 0 on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_probe_read_user($arg1, $arg2, (const void*)$arg3)")
    @NotUsableInJava
    public static long probeReadUser(Ptr<?> dst, @Unsigned int size, Ptr<?> src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Safely read a NUL-terminated string from user-space address {@code src} into {@code dst}.
     * Wraps {@code bpf_probe_read_user_str}.
     *
     * @param dst     destination buffer
     * @param size    maximum bytes to copy (including NUL terminator)
     * @param src     source user-space string pointer
     * @return length of the string (including NUL) on success; negative errno on failure
     */
    @BuiltinBPFFunction("bpf_probe_read_user_str($arg1, $arg2, (const void*)$arg3)")
    @NotUsableInJava
    public static long probeReadUserStr(Ptr<?> dst, @Unsigned int size, Ptr<?> src) {
        throw new MethodIsBPFRelatedFunction();
    }
}
