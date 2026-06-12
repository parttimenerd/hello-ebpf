package me.bechberger.ebpf.shared;

import java.lang.foreign.*;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.*;
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

    private static final GroupLayout RLIMIT_LAYOUT = MemoryLayout.structLayout(
            JAVA_LONG.withName("rlim_cur"), // Current (soft) limit
            JAVA_LONG.withName("rlim_max")  // Maximum (hard) limit
    );

    // Define the RLIMIT_MEMLOCK constant
    public static final int RLIMIT_MEMLOCK = 8;

    private static final HandlerWithErrno<Void> SET_RLIMIT_HANDLER = new HandlerWithErrno<>("setrlimit",
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, POINTER));

    /**
     * Set the resource limits for the current process using the {@code setrlimit} syscall
     * @param resource resource id
     * @param softLimit enforced limit by the kernel
     * @param hardLimit maximum limit that can be set
     * @return error
     */
    public static ResultAndErr<Void> setrlimit(int resource, long softLimit, long hardLimit) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment rlimit = arena.allocate(RLIMIT_LAYOUT);
            rlimit.set(JAVA_LONG, RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_cur")), softLimit);
            rlimit.set(JAVA_LONG, RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_max")), hardLimit);
            return SET_RLIMIT_HANDLER.call(resource, rlimit);
        }
    }

    /**
     * Set the RLIMIT_MEMLOCK to infinity, because ebpf needs to lock more memory
     * than allowed by default
     */
    public static ResultAndErr<Void> setRlimitMemlockToInfinity() {
        return setrlimit(RLIMIT_MEMLOCK, -1, -1);
    }

    // ---- mmap / munmap ------------------------------------------------------
    public static final int PROT_READ = 0x1;
    public static final int PROT_WRITE = 0x2;
    public static final int MAP_SHARED = 0x01;
    public static final int MAP_FIXED = 0x10;

    private static final HandlerWithErrno<MemorySegment> MMAP_HANDLE = new HandlerWithErrno<>("mmap",
            FunctionDescriptor.of(POINTER, POINTER, JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG));

    private static final HandlerWithErrno<Integer> MUNMAP_HANDLE = new HandlerWithErrno<>("munmap",
            FunctionDescriptor.of(JAVA_INT, POINTER, JAVA_LONG));

    /**
     * mmap a file descriptor into the process's address space.
     * Returns the result address as a {@code MemorySegment} of unspecified
     * size (caller is expected to {@code .reinterpret(size, ...)}). On error
     * the segment is {@code MAP_FAILED} (address = -1) and the errno field
     * of the {@code ResultAndErr} explains why.
     */
    public static ResultAndErr<MemorySegment> mmap(MemorySegment addr, long length, int prot, int flags, int fd, long offset) {
        return MMAP_HANDLE.call(addr, length, prot, flags, fd, offset);
    }

    /** munmap a previously mapped region. */
    public static ResultAndErr<Integer> munmap(MemorySegment addr, long length) {
        return MUNMAP_HANDLE.call(addr, length);
    }
}
