package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.*;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

public class PanamaUtil {

    public static String toString(MemorySegment segment) {
        return segment.getUtf8String(0);
    }

    public static MemorySegment lookup(String symbol) {
        return Linker.nativeLinker().defaultLookup().find(symbol)
                .or(() -> SymbolLookup.loaderLookup().find(symbol)).orElseThrow();
    }

    public static final AddressLayout POINTER = ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE));

    public static final int ERRNO_PERM_ERROR = 1;

    public static String errnoString(int error) {
        return Lib.strerror(error).getUtf8String(0);
    }

    public static MemorySegment allocateNullOrString(Arena arena, @Nullable String string) {
        if (string == null) {
            return MemorySegment.NULL;
        }
        return arena.allocateUtf8String(string);
    }
}
