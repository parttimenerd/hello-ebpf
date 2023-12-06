package me.bechberger.ebpf.bcc;

/**
 * Debug flags for BPF programs
 * <p/>
 * Copied from the bcc Python bindings
 */
public final class LogLevel {
    private LogLevel() {}
    /**
     * Debug output compiled LLVM IR.
     */
    public static final int DEBUG_LLVM_IR = 0x1;

    /**
     * Debug output loaded BPF bytecode and register state on branches.
     */
    public static final int DEBUG_BPF = 0x2;
    /**
     * Debug output pre-processor result.
     */
    public static final int DEBUG_PREPROCESSOR = 0x4;
    /**
     * Debug output ASM instructions embedded with source.
     */
    public static final int DEBUG_SOURCE = 0x8;
    /**
     * Debug output register state on all instructions in addition to DEBUG_BPF.
     */
    public static final int DEBUG_BPF_REGISTER_STATE = 0x10;
    /**
     * Debug BTF.
     */
    public static final int DEBUG_BTF = 0x20;
}
