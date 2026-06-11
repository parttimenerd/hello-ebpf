package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.raw.Lib_2;
import me.bechberger.ebpf.bpf.raw.libbpf_print_fn_t;
import me.bechberger.ebpf.shared.PanamaUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Captures libbpf's print output (which on Linux includes the kernel verifier's log
 * after a failed {@code bpf_object__load}). Used by {@link BPFProgram#loadProgram()}
 * so that verifier errors can be surfaced as part of the thrown
 * {@link BPFVerifierException} instead of being silently lost.
 *
 * <p>libbpf calls back via the {@code libbpf_print_fn_t} signature
 * {@code int (level, const char *fmt, va_list ap)}. The format string can only be
 * resolved by libc's {@code vsnprintf}; this class wires up that downcall, accumulates
 * the rendered text into a thread-local {@link StringBuilder}, and exposes
 * {@link #drainAndReset()} so callers can grab anything that arrived during the most
 * recent libbpf operation.</p>
 *
 * <p>The upcall stub is allocated in {@link Arena#global()} because libbpf retains the
 * pointer for the lifetime of the process — installing once is sufficient and safe.</p>
 */
public final class VerifierLogCapture {

    private VerifierLogCapture() {}

    private static final ThreadLocal<StringBuilder> BUFFER =
            ThreadLocal.withInitial(StringBuilder::new);

    /** Resolved on first install; vsnprintf(char *str, size_t size, const char *fmt, va_list ap). */
    private static volatile MethodHandle VSNPRINTF;

    private static volatile boolean installed = false;

    /**
     * Install the libbpf print callback (idempotent). Safe to call from many threads —
     * only the first invocation actually registers a callback.
     */
    public static synchronized void install() {
        if (installed) {
            return;
        }
        VSNPRINTF = Linker.nativeLinker().downcallHandle(
                PanamaUtil.lookup("vsnprintf"),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, ADDRESS));

        libbpf_print_fn_t.Function fn = VerifierLogCapture::onPrint;
        MemorySegment stub = libbpf_print_fn_t.allocate(fn, Arena.global());
        Lib_2.libbpf_set_print(stub);
        installed = true;
    }

    /**
     * Return everything captured on the current thread since the last drain, and clear
     * the buffer. Returns the empty string if nothing was captured.
     */
    public static String drainAndReset() {
        StringBuilder sb = BUFFER.get();
        if (sb.length() == 0) {
            return "";
        }
        String s = sb.toString();
        sb.setLength(0);
        return s;
    }

    /** libbpf print callback — formats the message via vsnprintf and appends it. */
    private static int onPrint(int level, MemorySegment fmt, MemorySegment ap) {
        try (Arena arena = Arena.ofConfined()) {
            // 4 KiB scratch is plenty for a single libbpf line; verifier emits many lines.
            final long size = 4096L;
            MemorySegment buf = arena.allocate(size, 1);
            int written;
            try {
                // On x86_64 Linux, va_list is a single-element array of __va_list_tag,
                // and is passed by reference — i.e. the `ap` MemorySegment we got from
                // libbpf is already the correct pointer to hand straight to vsnprintf.
                written = (int) VSNPRINTF.invokeExact(buf, size, fmt, ap);
            } catch (Throwable t) {
                // If vsnprintf fails, swallow — losing the message is preferable to
                // crashing the host process during BPF load error reporting.
                return 0;
            }
            if (written <= 0) {
                return 0;
            }
            int len = (int) Math.min(written, size - 1);
            byte[] bytes = new byte[len];
            MemorySegment.copy(buf, JAVA_BYTE, 0, bytes, 0, len);
            BUFFER.get().append(new String(bytes));
            return written;
        } catch (Throwable t) {
            return 0;
        }
    }
}
