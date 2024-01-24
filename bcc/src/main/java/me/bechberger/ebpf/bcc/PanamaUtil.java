package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Utility methods for Panama
 */
public class PanamaUtil {

    public static final char O_RDONLY = 0;
    public static final char O_WRONLY = 1;
    public static final char O_RDWR = 2;

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
     */
    public static MemorySegment lookup(String symbol) {
        return Linker.nativeLinker().defaultLookup().find(symbol)
                .or(() -> SymbolLookup.loaderLookup().find(symbol)).orElseThrow();
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
     * Wraps a method handle and captures the errno value
     */
    public record HandlerWithErrno<R>(MethodHandle handle) {

        public HandlerWithErrno(String symbol, FunctionDescriptor descriptor) {
            this(Linker.nativeLinker().downcallHandle(PanamaUtil.lookup(symbol), descriptor, Linker.Option.captureCallState("errno")));
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
                return new ResultAndErr<>((R) handle.invokeWithArguments(argsWithState), (int) errnoHandle.get(capturedState));
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
