package me.bechberger.ebpf.shared;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static me.bechberger.ebpf.shared.PanamaUtil.*;

/**
 * Wrapper for selected libc functions
 */
public class LibC {

    private final static HandlerWithErrno<Integer> OPEN_HANDLE = new HandlerWithErrno<>("open",
            FunctionDescriptor.of(JAVA_INT, PanamaUtil.POINTER, JAVA_INT));

    private final static HandlerWithErrno<Void> CLOSE_HANDLE = new HandlerWithErrno<>("close",
            FunctionDescriptor.of(JAVA_INT, JAVA_INT));

    /**
     * Call the {@code open} syscall, to open a file, returns the file descriptor
     */
    public static ResultAndErr<Integer> open(Path path, int flags) {
        try (Arena arena = Arena.ofConfined()) {
            return OPEN_HANDLE.call(arena.allocateFrom(path.toString()), flags);
        }
    }

    /**
     * Call the {@code close} syscall, to close a file descriptor
     */
    public static ResultAndErr<Void> close(int fd) {
        return CLOSE_HANDLE.call(fd);
    }
}
