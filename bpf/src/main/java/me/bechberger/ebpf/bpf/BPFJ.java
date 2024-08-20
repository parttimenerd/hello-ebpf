package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;

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
}