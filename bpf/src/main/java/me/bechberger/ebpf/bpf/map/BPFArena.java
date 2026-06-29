package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil.ResultAndErr;
import me.bechberger.ebpf.type.Ptr;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * eBPF arena map ({@code BPF_MAP_TYPE_ARENA}) — a shared, page-granular
 * memory region accessible from both BPF and user space.
 * <p>
 * Inside BPF, arena pointers live in clang address space 1
 * ({@code __attribute__((address_space(1)))}, spelled {@code __arena}); on
 * Clang 17+ with {@code __BPF_FEATURE_ADDR_SPACE_CAST} (which this project's
 * 6.17 kernel floor guarantees) the {@code cast_kern} / {@code cast_user}
 * macros are no-ops the compiler emits implicitly, so user code can mostly
 * ignore the address space distinction.
 * <p>
 * From user space, call {@link #userView()} to get a {@link MemorySegment}
 * mmap'd over the arena. The same bytes BPF wrote at offset N are visible
 * at the same offset N to user space.
 * <p>
 * Allocation inside BPF goes through
 * {@code BPFJ.bpfArenaAllocPages(arena, NULL, pageCount, NUMA_NO_NODE, 0)}
 * which lowers to the {@code bpf_arena_alloc_pages} kfunc.
 * <p>
 * Requires kernel ≥6.17 (project floor).
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_ARENA);
            __uint(map_flags, BPF_F_MMAPABLE);
            __uint(max_entries, $maxEntries);
        #ifdef __TARGET_ARCH_arm64
            __ulong(map_extra, 0x1ull << 32);
        #else
            __ulong(map_extra, 0x1ull << 44);
        #endif
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class($fd, $maxEntries)
        """)
public class BPFArena extends BPFMap {

    /** 4 KiB; matches the kernel's BPF arena page size. */
    public static final int PAGE_SIZE = 4096;

    private final int maxEntries;
    private MemorySegment userView;
    private final Arena lifetime = Arena.ofShared();

    public BPFArena(FileDescriptor fd, int maxEntries) {
        super(MapTypeId.ARENA, fd);
        this.maxEntries = maxEntries;
    }

    /** Number of pages the arena was sized to ({@code max_entries}). */
    public int pageCount() {
        return maxEntries;
    }

    /** Total arena size in bytes (pages × {@link #PAGE_SIZE}). */
    public long sizeBytes() {
        return (long) maxEntries * PAGE_SIZE;
    }

    /**
     * mmap the arena into the user-space address space and return a
     * {@link MemorySegment} covering its full byte range. Cached after the
     * first call; the segment's lifetime is tied to this {@code BPFArena}
     * (closed by {@link #close()}).
     * <p>
     * When {@code map_extra} is set in the cTemplate (it is, for predictable
     * BPF-side addresses), the kernel's {@code arena_get_unmapped_area}
     * requires {@code mmap()} to be called with {@code addr = map_extra} and
     * {@code MAP_FIXED} — passing {@code NULL} returns EINVAL.
     */
    public synchronized MemorySegment userView() {
        if (userView != null) {
            return userView;
        }
        long size = sizeBytes();
        long mapExtra = getInfo().mapExtra();
        MemorySegment requestedAddr = mapExtra != 0
                ? MemorySegment.ofAddress(mapExtra)
                : MemorySegment.NULL;
        int flags = LibC.MAP_SHARED | (mapExtra != 0 ? LibC.MAP_FIXED : 0);
        ResultAndErr<MemorySegment> r = LibC.mmap(requestedAddr, size,
                LibC.PROT_READ | LibC.PROT_WRITE, flags, fd.fd(), 0);
        MemorySegment raw = r.result();
        if (raw == null || raw.address() == -1L) {
            throw new BPFError("BPFArena mmap failed", r.err());
        }
        userView = raw.reinterpret(size, lifetime, seg -> {
            LibC.munmap(seg, size);
        });
        return userView;
    }

    /**
     * Pointer to the {@code idx}-th 8-byte word of this arena's page-0. Used by
     * {@link me.bechberger.ebpf.bpf.UserspaceSchedulerBase} to maintain the idle
     * CPU bitmap via atomic ops on each word.
     *
     * <p>Lowers to {@code (unsigned long *)((char *)arena + 8 * idx)}.
     *
     * @param idx 0-based word index; word 0 covers CPUs 0–63, word 1 covers 64–127, etc.
     * @return pointer to the 8-byte word at the given index
     */
    @BuiltinBPFFunction("(unsigned long *)((char *)$this + 8 * $arg1)")
    @NotUsableInJava
    public Ptr<Long> bpf_arena_word_at(long idx) {
        throw new MethodIsBPFRelatedFunction();
    }

    @Override
    public void close() {
        try {
            lifetime.close();
        } catch (RuntimeException ignored) {
            // already closed or never opened — fine
        }
        super.close();
    }
}
