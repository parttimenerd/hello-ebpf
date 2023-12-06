package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.*;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Utility methods for Panama
 */
public class PanamaUtil {

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
}
