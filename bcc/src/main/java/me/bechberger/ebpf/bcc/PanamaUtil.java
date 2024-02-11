package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.util.NoSuchElementException;
import java.util.function.Function;
import java.util.function.Supplier;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Utility methods for Panama
 */
public class PanamaUtil {

    public static final char O_RDONLY = 0;
    public static final char O_WRONLY = 1;
    public static final char O_RDWR = 2;

    private static final boolean HAS_BCC_BATCH_FUNCTIONS;
    static {
        boolean b = false;
        try {
            PanamaUtil.lookup("bpf_lookup_and_delete_batch");
            b = true;
        } catch (NoSuchElementException e) {
            // ignore
        }
        HAS_BCC_BATCH_FUNCTIONS = b;
    }

    /**
     * Convert a memory segment to a string, returns null if segment is NULL
     */
    public static String toString(MemorySegment segment) {
        if (segment == MemorySegment.NULL) {
            return null;
        }
        return segment.getUtf8String(0);
    }

    /**
     * Lookup a symbol in the current process
     *
     * @throws NoSuchElementException if the symbol is not found
     */
    public static MemorySegment lookup(String symbol) {
        return Linker.nativeLinker().defaultLookup().find(symbol)
                .or(() -> SymbolLookup.loaderLookup().find(symbol))
                .orElseThrow(() -> new NoSuchElementException("Symbol not found: " + symbol));
    }

    /**
     * Check if the batch functions of bcc (like bpf_lookup_and_delete_batch) are available.
     * <p>
     * Some versions of bcc (on some platforms) apparently do not have these functions.
     * @return true if the batch functions are available
     */
    public static boolean hasBCCBatchFunctions() {
        return HAS_BCC_BATCH_FUNCTIONS;
    }

    /**
     * Pointer type
     */
    public static final AddressLayout POINTER = ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE));

    /**
     * No such file or directory errno value
     */

    public static final int ERRNO_ENOENT = 2;

    /**
     * errno value for permission errors
     */
    public static final int ERRNO_PERM_ERROR = 1;

    /**
     * Format errno to string using {@link Lib#strerror}
     */
    public static String errnoString(int error) {
        return Lib.strerror(error).getUtf8String(0);
    }

    /**
     * Allocate a string or NULL in the given arena
     */
    public static MemorySegment allocateNullOrString(Arena arena, @Nullable String string) {
        if (string == null) {
            return MemorySegment.NULL;
        }
        return arena.allocateUtf8String(string);
    }

    /** Result and errno */
    public record ResultAndErr<R>(R result, int err) {
    }

    /**
     * Wraps a method handle and captures the errno value,
     * but only lookup the handle when it is actually used
     */
    public static class HandlerWithErrno<R> {

        private MethodHandle handle = null;
        private final Supplier<MethodHandle> handleSupplier;

        public HandlerWithErrno(String symbol, FunctionDescriptor descriptor) {
            handleSupplier = () -> Linker.nativeLinker()
                    .downcallHandle(PanamaUtil.lookup(symbol), descriptor,
                            Linker.Option.captureCallState("errno"));
        }

        private MethodHandle getHandle() {
            if (handle == null) {
                handle = handleSupplier.get();
            }
            return handle;
        }

        @SuppressWarnings("unchecked")
        public ResultAndErr<R> call(Arena arena, Object... args) {
            StructLayout capturedStateLayout = Linker.Option.captureStateLayout();
            VarHandle errnoHandle =
                    capturedStateLayout.varHandle(
                            MemoryLayout.PathElement.groupElement("errno"));
            MemorySegment capturedState = arena.allocate(capturedStateLayout);
            try {
                Object[] argsWithState = new Object[args.length + 1];
                argsWithState[0] = capturedState;
                System.arraycopy(args, 0, argsWithState, 1, args.length);
                return new ResultAndErr<>((R) getHandle().invokeWithArguments(argsWithState),
                        (int) errnoHandle.get(capturedState));
            } catch (Throwable throwable) {
                throw new RuntimeException(throwable);
            }
        }

        public ResultAndErr<R> call(Object... args) {
            try (Arena arena = Arena.ofConfined()) {
                return call(arena, args);
            }
        }
    }

    public static long padSize(long size) {
        return (size + 7) & ~7;
    }
}
