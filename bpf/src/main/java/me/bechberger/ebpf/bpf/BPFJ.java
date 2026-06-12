package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;

import java.util.function.BiFunction;

/**
 * Helper functions for the BPF code, to make its usage more convenient with Java
 */
public class BPFJ {

    /**
     * Print a message to the trace log
     * <p>
     * Example: {@snippet :
     *     BPFJ.bpf_trace_printk("Hello, %s from BPF and more!", "World");
     *}
     * @param fmt format string
     * @param args arguments to the format string
     */
    @BuiltinBPFFunction("bpf_trace_printk($arg1, sizeof($arg1), $args2_)")
    @NotUsableInJava
    public static void bpf_trace_printk(String fmt, Object... args) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Wrapper for the BPF_SNPRINTF macro
     * <p>
     * Example: {@snippet :
     *     @Size(16) String out = "";
     *     BPFJ.bpf_snprintf(out, "Hello, %s!", "World");
     *}
     * @param fmt format string
     * @param args arguments to the format string
     */
    @BuiltinBPFFunction("BPF_SNPRINTF($arg1, sizeof($arg1), $arg2, $args3_)")
    @NotUsableInJava
    public static void bpf_snprintf(String out, String fmt, Object... args) {
        throw new MethodIsBPFRelatedFunction();
    }

    // add a helper for the atomic increment functions
    // __sync_add_and_fetch(&var, increment)

    /**
     * Atomically add to a variable and return the new value
     */
    @BuiltinBPFFunction("__sync_add_and_fetch($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_add_and_fetch(Ptr<T> var, T increment) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Atomically subtract from a variable and return the new value
     */
    @BuiltinBPFFunction("__sync_sub_and_fetch($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_sub_and_fetch(Ptr<T> var, T decrement) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Atomically increment a variable and return the old value
     */
    @BuiltinBPFFunction("__sync_fetch_and_add($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_fetch_and_add(Ptr<T> var, T increment) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Atomically decrement a variable and return the old value
     */
    @BuiltinBPFFunction("__sync_fetch_and_sub($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_fetch_and_sub(Ptr<T> var, T decrement) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("__sync_fetch_and_or($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_fetch_and_or(Ptr<T> var, T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("__sync_fetch_and_and($arg1, $arg2)")
    @NotUsableInJava
    public static <T extends Number> T sync_fetch_and_and(Ptr<T> var, T value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Size of the type in bytes
     * <p>
     * Example: {@snippet :
     *    BPFJ.<Integer>sizeof() == 4;
     *    BPFJ.<Long>sizeof() == 8;
     *}
     * @return int size of the type in bytes
     * @param <T> type, has to be passed
     */
    @BuiltinBPFFunction("sizeof($T1)")
    @NotUsableInJava
    public static <T> int sizeof() {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("sizeof($arg1)")
    @NotUsableInJava
    public static int sizeof(Object obj) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Set the value of a field of an object in BPF, even if the object
     * would be immutable in Java
     * <p>
     * Example: {@snippet :
     *     @Type record MyRecord(int a, int b) {}
     *     MyRecord record = new MyRecord(1, 2);
     *     BPFJ.setField(record, "a", 3);
     *}
     */
    @BuiltinBPFFunction("($arg1).$str$arg2 = $arg3")
    @NotUsableInJava
    public static <T> void setField(T val, String fieldName, Object value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source string from the kernel and write it to the destination
     * @see BPFHelpers#bpf_probe_read_kernel_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static void bpf_probe_read_kernel_str(char[] dest, String source) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source string from the kernel and write it to the destination
     * @see BPFHelpers#bpf_probe_read_kernel_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static void bpf_probe_read_kernel_str(String dest, char[] source) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source string from the kernel and write it to the destination
     * @see BPFHelpers#bpf_probe_read_kernel_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static void bpf_probe_read_kernel_str(String dest, String source) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source string from the kernel and write it to the destination
     * @see BPFHelpers#bpf_probe_read_kernel_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static long bpf_probe_read_kernel_str(char[] dest, char[] source) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source string from the kernel and write it to the destination
     * @see BPFHelpers#bpf_probe_read_kernel_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static long bpf_probe_read_kernel_str(char[] dest, Ptr<Character> source) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the source object from the kernel and write it to the destination
     * @param dest destination object, has to be a variable
     * @see BPFHelpers#bpf_probe_read_kernel(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_kernel(&$arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
    public static <T> long bpf_probe_read_kernel(T dest, Ptr<T> src) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, $arg2, $arg3)")
    public static long bpf_probe_read_kernel_str(String val, int size, String filename) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, $arg2, $arg3)")
    public static long bpf_probe_read_kernel_str(String val, int size, Ptr<Character> filename) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the null-terminated source string from the user space
     * and write it to the destination
     * @see BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction
    public static <T> long bpf_probe_read_user_str(String dest, int size, String src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the null-terminated source string from the user space
     * and write it to the destination
     * @see BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_user_str($arg1, sizeof($arg1), $arg2)")
    public static <T> long bpf_probe_read_user_str(String dest, String src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a {@code continue} in lambda blocks
     */
    @BuiltinBPFFunction("continue")
    public static void _continue() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a {@code break} in lambda blocks
     */
    @BuiltinBPFFunction("break")
    public static void _break() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a {@code return} in lambda blocks
     */
    @BuiltinBPFFunction("return $arg1")
    public static Object _return(Object value) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Create a {@code return} in lambda blocks
     */
    @BuiltinBPFFunction("return")
    public static void _return() {
        throw new MethodIsBPFRelatedFunction();
    }

    // -------------------------------------------------------------------------
    // Common context helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the PID (user-space process ID) of the current task.
     * <p>Lowers to the lower 32 bits of {@code bpf_get_current_pid_tgid()}.
     */
    @BuiltinBPFFunction("((u32)(bpf_get_current_pid_tgid()))")
    @NotUsableInJava
    public static int currentPid() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the TGID (user-space thread group ID, i.e. {@code getpid()} in C)
     * of the current task.
     * <p>Lowers to the upper 32 bits of {@code bpf_get_current_pid_tgid()}.
     */
    @BuiltinBPFFunction("((u32)(bpf_get_current_pid_tgid() >> 32))")
    @NotUsableInJava
    public static int currentTgid() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the current CPU identifier (0-based).
     * <p>Lowers to {@code bpf_get_smp_processor_id()}.
     */
    @BuiltinBPFFunction("bpf_get_smp_processor_id()")
    @NotUsableInJava
    public static int currentCpuId() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the current time in nanoseconds since boot.
     * <p>Lowers to {@code bpf_ktime_get_ns()}.
     */
    @BuiltinBPFFunction("bpf_ktime_get_ns()")
    @NotUsableInJava
    public static long currentNs() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Copies the current task's command name (up to 15 characters + NUL) into
     * the supplied {@code buf} and returns the number of bytes written.
     * <p>
     * Typical usage:
     * <pre>{@code
     *   @Size(16) char[] comm = BPFJ.charBuf(16);
     *   BPFJ.getCurrentComm(comm);
     * }</pre>
     * <p>Lowers to {@code bpf_get_current_comm($arg1, sizeof($arg1))}.
     */
    @BuiltinBPFFunction("bpf_get_current_comm($arg1, sizeof($arg1))")
    @NotUsableInJava
    public static long getCurrentComm(char[] buf) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Same as {@link #getCurrentComm(char[])} but accepts a {@code String}
     * annotated with {@link me.bechberger.ebpf.annotations.Size}.
     */
    @BuiltinBPFFunction("bpf_get_current_comm($arg1, sizeof($arg1))")
    @NotUsableInJava
    public static long getCurrentComm(String buf) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Allocates a zero-initialised character buffer of compile-time size {@code n}.
     * <p>
     * This is the blessed pattern for declaring a char buffer to pass to
     * {@code bpf_get_current_comm} and friends instead of the rejected
     * {@code @Size(N) String comm = new String()}.
     * <p>
     * Usage:
     * <pre>{@code
     *   @Size(16) char[] comm = BPFJ.charBuf(16);
     * }</pre>
     * <p>Lowers to {@code char $arr[N] = {}}, where {@code N} is the literal
     * passed as {@code n}.
     */
    @BuiltinBPFFunction("{}")
    @NotUsableInJava
    public static char[] charBuf(int n) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Run {@code body} {@code count} times via {@code bpf_loop}, passing {@code ctx}
     * to every iteration.
     * <p>
     * Lowers to {@code bpf_loop(count, &__bpf_lambda_..., ctx, 0)} where the lambda
     * is lifted to a top-level static {@code __always_inline} C function with the
     * shape {@code int (*)(u32 index, void *ctx)}. The lambda body must NOT capture
     * locals from the enclosing method — pass state through {@code ctx} instead.
     * <p>
     * Return values from the lambda follow {@code bpf_loop} semantics: {@code 0} to
     * continue, {@code 1} to break, anything else is an error.
     * <p>
     * Example:
     * <pre>{@code
     *   BPFJ.bpfLoop(10, (i, ctx) -> {
     *       BPFJ.bpf_trace_printk("iter %d", i);
     *       return 0;
     *   }, null);
     * }</pre>
     * Requires kernel ≥5.17.
     */
    @BuiltinBPFFunction("bpf_loop($arg1, $func2, $arg3, 0)")
    @NotUsableInJava
    public static <C> void bpfLoop(int count, BiFunction<Integer, C, Integer> body, C ctx) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * CO-RE field-existence check. Returns {@code true} at runtime iff the
     * named field is present in the target kernel's BTF.
     * <p>
     * Lowers to {@code bpf_core_field_exists(((T*)0)->fieldName)}. Use to
     * gate access to fields that came or went between kernel versions —
     * the verifier dead-code-eliminates the false branch when the field is
     * known absent.
     * <pre>{@code
     *   if (BPFJ.<task_struct>coreFieldExists("__state")) {
     *       // path that reads the new field name (≥5.14)
     *   } else {
     *       // path that reads the old field name (<5.14)
     *   }
     * }</pre>
     * Requires kernel BTF support and {@code bpf_core_read.h} (already
     * included by default in hello-ebpf).
     */
    @BuiltinBPFFunction("bpf_core_field_exists((($T1*)0)->$str$arg1)")
    @NotUsableInJava
    public static <T> boolean coreFieldExists(String fieldName) {
        throw new MethodIsBPFRelatedFunction();
    }
}