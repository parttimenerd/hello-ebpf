package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
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
    @NotUsableInJava
    public static long bpf_probe_read_kernel_str(String val, int size, String filename) {
        throw new MethodIsBPFRelatedFunction();
    }

    @BuiltinBPFFunction("bpf_probe_read_kernel_str($arg1, $arg2, $arg3)")
    @NotUsableInJava
    public static long bpf_probe_read_kernel_str(String val, int size, Ptr<Character> filename) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the null-terminated source string from the user space
     * and write it to the destination
     * @see BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction
    @NotUsableInJava
    public static <T> long bpf_probe_read_user_str(String dest, int size, String src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Read the null-terminated source string from the user space
     * and write it to the destination
     * @see BPFHelpers#bpf_probe_read_user_str(Ptr, int, Ptr)
     */
    @BuiltinBPFFunction("bpf_probe_read_user_str($arg1, sizeof($arg1), $arg2)")
    @NotUsableInJava
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
     * <p>
     * <b>The field name must be a valid C identifier of {@code T} at
     * compile time</b> — i.e. {@code T} must have that field in the BTF
     * the program is compiled against. This is a CO-RE macro, not a free
     * runtime string lookup: clang refuses to compile if the field doesn't
     * resolve. Use it to gate access to fields that exist in *your* compile
     * kernel but may be absent on older targets.
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

    /**
     * Allocate {@code pageCount} contiguous pages from {@code arena}.
     * Lowers to the {@code bpf_arena_alloc_pages} kfunc. Returns an arena
     * pointer (clang AS1) — the caller should annotate the receiving variable
     * with {@code @InArena} so the Translator emits the {@code __arena}
     * qualifier on the declaration.
     * <p>
     * Pass {@link me.bechberger.ebpf.runtime.MmConstants#NUMA_NO_NODE} for
     * {@code nodeId} when no NUMA preference is needed. {@code addrHint} is
     * usually {@code null}; pass a non-null pointer only to request a
     * specific arena offset.
     */
    @BuiltinBPFFunction("bpf_arena_alloc_pages(&$arg1, $arg2, $arg3, $arg4, $arg5)")
    @NotUsableInJava
    public static <T> Ptr<T> bpfArenaAllocPages(BPFArena arena, Ptr<T> addrHint,
                                                int pageCount, int nodeId, long flags) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Free {@code pageCount} pages starting at {@code ptr} back to {@code arena}.
     * Lowers to the {@code bpf_arena_free_pages} kfunc.
     */
    @BuiltinBPFFunction("bpf_arena_free_pages(&$arg1, $arg2, $arg3)")
    @NotUsableInJava
    public static <T> void bpfArenaFreePages(BPFArena arena, Ptr<T> ptr, int pageCount) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Cast a user-space (AS0) pointer to a kernel-space (AS1, {@code __arena})
     * pointer. With {@code __BPF_FEATURE_ADDR_SPACE_CAST} (clang 17+, kernel
     * ≥6.17) this is normally implicit; expose it here for the rare cases
     * where the compiler can't infer the cast (e.g. round-tripping through
     * {@code u64}).
     */
    @BuiltinBPFFunction("((__arena typeof(*($arg1)) *)($arg1))")
    @NotUsableInJava
    public static <T> Ptr<T> castKern(Ptr<T> p) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Cast a kernel-space ({@code __arena}, AS1) pointer to a user-space
     * (AS0) pointer. See {@link #castKern} for when this is needed.
     */
    @BuiltinBPFFunction("((void *)($arg1))")
    @NotUsableInJava
    public static <T> Ptr<T> castUser(Ptr<T> p) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Set a {@code bpf_timer}'s callback to a {@code @BPFFunction} method reference.
     *
     * <p>Java overload of {@code BPFHelpers.bpf_timer_set_callback} whose second parameter is
     * typed as a functional interface so {@code this::onTick} compiles. The compiler plugin
     * lowers the method reference to the bare C identifier of the target {@code @BPFFunction},
     * which is what the verifier-callable {@code bpf_timer_set_callback} kernel helper expects.
     *
     * <p>Callback signature must match the BPF timer ABI: {@code (Ptr<map>, Ptr<K>, Ptr<V>) -> int}.
     *
     * <pre>{@code
     *   bpf_timer_set_callback(Ptr.of(val.timer), this::timerCallback);
     * }</pre>
     *
     * @param timer    pointer to the {@code bpf_timer} stored in a map value
     * @param callback method reference to a {@code @BPFFunction} matching the timer ABI
     */
    @BuiltinBPFFunction("bpf_timer_set_callback($arg1, $arg2)")
    @NotUsableInJava
    public static <K, V> long bpf_timer_set_callback(
            Ptr<bpf_timer> timer,
            TriFunction<Ptr<?>, Ptr<K>, Ptr<V>, Integer> callback) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns a uniformly random {@code u32} via {@code bpf_get_prandom_u32()}.
     *
     * <p>The kernel seeds the per-CPU PRNG at program load time.  Use
     * {@link #bpfRandBounded(long)} for a bias-free bounded draw.
     */
    @BuiltinBPFFunction("bpf_get_prandom_u32()")
    @NotUsableInJava
    public static @Unsigned int bpfRand() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns a uniformly random {@code u32} in {@code [0, limit)}, bias-free
     * via Lemire's 32-bit algorithm (multiply-high, no rejection loop).
     *
     * <p>Equivalent to:
     * <pre>{@code (u32)((u64)bpf_get_prandom_u32() * (u64)(limit) >> 32)}</pre>
     *
     * @param limit exclusive upper bound; must be &gt; 0
     */
    @BuiltinBPFFunction("((u32)((u64)bpf_get_prandom_u32() * (u64)($arg1) >> 32))")
    @NotUsableInJava
    public static @Unsigned int bpfRandBounded(@Unsigned long limit) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Userspace helper: allocate a {@code bpf_timer} whose internal {@code __opaque}
     * slot is a zeroed {@code long[2]} of the right size for the kernel timer state.
     *
     * <p>Use when seeding a map entry that contains a {@code bpf_timer} field — a
     * default-constructed {@code bpf_timer} has {@code __opaque == null}, which the
     * struct serializer dereferences and crashes on. Calling this once at seed time
     * avoids the boilerplate.
     *
     * <pre>{@code
     *   var v = new TimerVal();
     *   v.timer = BPFJ.newZeroedTimer();
     *   map.put(0, v);
     * }</pre>
     */
    public static bpf_timer newZeroedTimer() {
        var t = new bpf_timer();
        t.__opaque = new long[2];
        return t;
    }

    // -----------------------------------------------------------------------
    // Process / task helpers
    // -----------------------------------------------------------------------

    /**
     * Returns a BTF-tracked pointer to the {@code task_struct} of the currently
     * executing task.
     *
     * <p>Unlike the raw {@code bpf_get_current_task()} which returns an opaque
     * {@code unsigned long}, this variant returns a proper {@code Ptr<task_struct>}
     * that participates in CO-RE field access and allows the BPF verifier to check
     * field types.
     *
     * <p>Equivalent to the kernel helper {@code bpf_get_current_task_btf()}.
     */
    @BuiltinBPFFunction("bpf_get_current_task_btf()")
    @NotUsableInJava
    public static Ptr<task_struct> currentTask() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Sends the given signal to the current process.
     *
     * <p>The signal is sent to the thread group of the task that triggered the
     * BPF program. Equivalent to {@code bpf_send_signal(sig)}.
     *
     * <p>Requires kernel ≥ 5.3. Returns 0 on success, negative errno otherwise.
     *
     * @param sig signal number, e.g. {@code 9} for {@code SIGKILL}
     * @return 0 on success, negative errno on error
     */
    @BuiltinBPFFunction("bpf_send_signal($arg1)")
    @NotUsableInJava
    public static long sendSignal(@Unsigned int sig) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Sends the given signal to the current <em>thread</em> only (not the whole
     * process). Equivalent to {@code bpf_send_signal_thread(sig)}.
     *
     * <p>Requires kernel ≥ 5.10.
     *
     * @param sig signal number
     * @return 0 on success, negative errno on error
     */
    @BuiltinBPFFunction("bpf_send_signal_thread($arg1)")
    @NotUsableInJava
    public static long sendSignalThread(@Unsigned int sig) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Overrides the return value of the probed function.
     *
     * <p>Only available in {@code kretprobe} programs. Equivalent to
     * {@code bpf_override_return(ctx, retval)}.
     *
     * <p>Requires kernel ≥ 4.16 and the kernel to be compiled with
     * {@code CONFIG_BPF_KPROBE_OVERRIDE}.
     *
     * @param ctx    the kretprobe context (pt_regs)
     * @param retval the return value to inject
     * @return 0 on success, negative errno on error
     */
    @BuiltinBPFFunction("bpf_override_return($arg1, $arg2)")
    @NotUsableInJava
    public static long overrideReturn(Ptr<?> ctx, long retval) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the monotonic nanosecond timestamp relative to boot time (includes suspend time).
     *
     * <p>Unlike {@link #currentNs()} (which uses {@code CLOCK_MONOTONIC} and excludes suspend),
     * this uses {@code CLOCK_BOOTTIME} — useful for correlating with userspace {@code CLOCK_BOOTTIME}
     * timestamps.
     *
     * <p>Lowers to {@code bpf_ktime_get_boot_ns()}.
     */
    @BuiltinBPFFunction("bpf_ktime_get_boot_ns()")
    @NotUsableInJava
    public static @Unsigned long currentBootNs() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Reads {@code sizeof(T)} bytes from user-space memory at {@code src} into {@code dst}.
     *
     * <p>Lowers to {@code bpf_probe_read_user(&$arg1, sizeof(*$arg1), $arg2)}.
     *
     * @param dst destination (BPF-accessible)
     * @param src user-space pointer to read from
     * @return 0 on success, negative errno on error
     */
    @BuiltinBPFFunction("bpf_probe_read_user(&$arg1, sizeof(*&$arg1), $arg2)")
    @NotUsableInJava
    public static <T> long bpf_probe_read_user(T dst, Ptr<T> src) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Returns the NUMA node ID of the current CPU.
     *
     * <p>Lowers to {@code bpf_get_numa_node_id()}.
     */
    @BuiltinBPFFunction("bpf_get_numa_node_id()")
    @NotUsableInJava
    public static int getNumaNodeId() {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Redirect the packet to the network device {@code ifindex} at the end
     * of the XDP or TC hook.
     *
     * <p>The redirect is not performed immediately — return
     * {@code xdp_action.XDP_REDIRECT} (or {@code TC_ACT_REDIRECT}) to
     * commit it.
     *
     * <p>Lowers to {@code bpf_redirect(ifindex, flags)}.
     *
     * @param ifindex target network interface index
     * @param flags   reserved, must be 0
     * @return {@code XDP_REDIRECT} on success, {@code XDP_ABORTED} on failure
     */
    @BuiltinBPFFunction("bpf_redirect($arg1, $arg2)")
    @NotUsableInJava
    public static @Unsigned long bpfRedirect(@Unsigned long ifindex, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Redirect the packet using a devmap, sockmap, or xskmap.
     *
     * <p>Returns {@code XDP_REDIRECT} on success, {@code XDP_ABORTED} on
     * failure.  Commit the redirect by returning the result as the XDP action.
     *
     * <p>Lowers to {@code bpf_redirect_map($arg1, $arg2, $arg3)}.
     *
     * @param map   pointer to a {@code BPFDevMap}, {@code BPFXskMap}, or {@code BPFSockMap}
     * @param key   lookup key (e.g. CPU id for devmap, queue id for xskmap)
     * @param flags {@code XDP_PASS} or {@code XDP_DROP} as fallback if the entry is absent
     * @return {@code XDP_REDIRECT} on success, the fallback action otherwise
     */
    @BuiltinBPFFunction("bpf_redirect_map($arg1, $arg2, $arg3)")
    @NotUsableInJava
    public static @Unsigned long bpfRedirectMap(Ptr<?> map, @Unsigned long key, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }
}