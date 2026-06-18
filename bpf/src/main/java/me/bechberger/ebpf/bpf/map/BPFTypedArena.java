package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.shared.LibC;
import me.bechberger.ebpf.shared.PanamaUtil.ResultAndErr;
import me.bechberger.ebpf.type.BPFType;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;

/**
 * Typed eBPF arena map — a shared, page-granular memory region accessible
 * from both BPF and user space, with record-shaped typed accessors.
 *
 * <p>Declare a fixed number of slots of type {@code T} using
 * {@code @BPFMapDefinition(maxEntries = N)}. The kernel map is sized to
 * the smallest whole number of 4 KiB pages that holds {@code N} slots.
 *
 * <pre>{@code
 * @Type record Item(int id, long value) {}
 *
 * @BPFMapDefinition(maxEntries = 16)
 * BPFTypedArena<Item> arena;
 * }</pre>
 *
 * <h3>User-side access</h3>
 * <pre>{@code
 * arena.set(0, new Item(7, 0xCAFEBABEL));
 * Item item = arena.get(0);            // parsed via BPFType<Item>
 * int count = arena.size();            // 16
 * }</pre>
 *
 * <h3>Atomic access (long fields)</h3>
 * <pre>{@code
 * long old = arena.atomicGetAndAdd(0, fieldOffsetBytes, 1L);
 * boolean swapped = arena.atomicCompareAndSet(0, fieldOffsetBytes, expected, update);
 * }</pre>
 * Use {@link BPFType#layout()} offsets or hard-coded field offsets derived
 * from the BPFType to locate individual fields within a slot.
 *
 * <h3>BPF-side access</h3>
 * Allocate pages with {@code BPFJ.bpfArenaAllocPages} and access via an
 * {@code @InArena Ptr<T>}. The shared memory is coherent — both sides see
 * the same bytes.
 *
 * <p>Requires kernel ≥ 6.17 (project floor).
 *
 * @param <T> the element type; must be a {@code @Type}-annotated record
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_ARENA);
            __uint(map_flags, BPF_F_MMAPABLE);
            __uint(max_entries, ($maxEntries * sizeof($c1) + 4095) / 4096);
        #ifdef __TARGET_ARCH_arm64
            __ulong(map_extra, 0x1ull << 32);
        #else
            __ulong(map_extra, 0x1ull << 44);
        #endif
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1, $maxEntries)
        """)
public class BPFTypedArena<T> extends BPFMap {

    /** 4 KiB; matches the kernel's BPF arena page granularity. */
    public static final int PAGE_SIZE = 4096;

    private final BPFType<T> valueType;
    private final int maxItems;
    private final long itemStride;   // sizePadded to keep natural alignment

    private MemorySegment userView;
    private final Arena lifetime = Arena.ofShared();

    // VarHandle for atomic long access within a slot.
    // Uses natural 8-byte alignment — callers must pass field offsets that are
    // a multiple of 8. @Type record layouts from BPFType always honour this
    // (longs are 8-byte-aligned in the generated C structs).
    private static final VarHandle LONG_VH = ValueLayout.JAVA_LONG.varHandle();

    public BPFTypedArena(FileDescriptor fd, BPFType<T> valueType, int maxItems) {
        super(MapTypeId.ARENA, fd);
        if (maxItems <= 0) throw new IllegalArgumentException("BPFTypedArena requires maxItems > 0, got " + maxItems);
        this.valueType = valueType;
        this.maxItems = maxItems;
        this.itemStride = valueType.sizePadded();
    }

    /** Number of typed slots in this arena. */
    public int size() {
        return maxItems;
    }

    /**
     * Returns the byte offset of {@code fieldName} within a single {@code T} slot,
     * using the same layout that {@link BPFType} uses for {@code parseMemory}/{@code setMemory}.
     *
     * <p>Use this to drive the atomic helpers without hard-coding magic byte offsets:
     * <pre>{@code
     *   long off = arena.fieldOffset("value");  // e.g. 8 for Item(int id, long value)
     *   arena.atomicGetAndAdd(0, off, 1L);
     * }</pre>
     *
     * <p>For non-struct arena types (e.g. {@code BPFTypedArena<Long>}) returns {@code 0L}.
     *
     * @throws IllegalArgumentException if no field named {@code fieldName} exists in a struct type
     */
    public long fieldOffset(String fieldName) {
        if (valueType instanceof BPFType.BPFStructType<?> st) {
            for (var member : st.members()) {
                if (member.name().equals(fieldName)) {
                    return member.offset();
                }
            }
            throw new IllegalArgumentException(
                    "No field '" + fieldName + "' in struct " + valueType.getClass().getSimpleName()
                            + ". Available fields: " + st.members().stream()
                            .map(m -> m.name()).collect(java.util.stream.Collectors.joining(", ")));
        }
        // Primitive arena types have a single value at offset 0.
        return 0L;
    }

    /** Total bytes available (ceiled to a page boundary). */
    public long sizeBytes() {
        return ceilToPage(itemStride * maxItems);
    }

    private static long ceilToPage(long bytes) {
        return ((bytes + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    }

    /**
     * Read slot {@code i} as a parsed {@code T} instance.
     * Both BPF and user-space writes to this slot are immediately visible here
     * (shared mmap — no syscall required).
     *
     * @throws IndexOutOfBoundsException if {@code i} is out of range
     */
    public T get(int i) {
        checkBounds(i);
        return valueType.parseMemory(sliceAt(i));
    }

    /**
     * Write {@code value} into slot {@code i}.
     * The bytes are immediately visible to BPF code (shared mmap).
     *
     * @throws IndexOutOfBoundsException if {@code i} is out of range
     */
    public void set(int i, T value) {
        checkBounds(i);
        valueType.setMemory(sliceAt(i), value);
    }

    // -------------------------------------------------------------------------
    // Atomic helpers — operate on a {@code long} field within a slot.
    // Use field offsets derived from BPFType.layout() or the @Type record layout.
    // fieldOffset must be a multiple of 8 (longs are always 8-byte-aligned in
    // BPFType-generated structs). Violating this throws on ARM and produces
    // undefined behaviour on x86 hardware atomics.
    // -------------------------------------------------------------------------

    /**
     * Atomically adds {@code delta} to the {@code long} at byte offset
     * {@code fieldOffset} within slot {@code i} and returns the previous value.
     *
     * <p>{@code fieldOffset} must be a multiple of 8.
     */
    public long atomicGetAndAdd(int i, long fieldOffset, long delta) {
        checkBounds(i);
        return (long) LONG_VH.getAndAdd(userView(), slotOffset(i) + fieldOffset, delta);
    }

    /**
     * Atomically compares the {@code long} at byte offset {@code fieldOffset}
     * within slot {@code i} with {@code expected}: if equal, stores {@code update}
     * and returns {@code true}; otherwise returns {@code false}.
     *
     * <p>{@code fieldOffset} must be a multiple of 8.
     */
    public boolean atomicCompareAndSet(int i, long fieldOffset, long expected, long update) {
        checkBounds(i);
        return (boolean) LONG_VH.compareAndSet(userView(), slotOffset(i) + fieldOffset, expected, update);
    }

    /**
     * Atomically reads the {@code long} at byte offset {@code fieldOffset}
     * within slot {@code i} with volatile semantics.
     *
     * <p>{@code fieldOffset} must be a multiple of 8.
     */
    public long atomicGetLong(int i, long fieldOffset) {
        checkBounds(i);
        return (long) LONG_VH.getVolatile(userView(), slotOffset(i) + fieldOffset);
    }

    /**
     * Atomically stores {@code value} into the {@code long} at byte offset
     * {@code fieldOffset} within slot {@code i} with volatile semantics.
     */
    public void atomicSetLong(int i, long fieldOffset, long value) {
        checkBounds(i);
        LONG_VH.setVolatile(userView(), slotOffset(i) + fieldOffset, value);
    }

    /**
     * Returns the underlying mmap'd {@link MemorySegment} covering the full arena.
     * Prefer {@link #get}/{@link #set} for typed access; use this for raw/legacy
     * operations only.
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
            throw new BPFError("BPFTypedArena mmap failed", r.err());
        }
        userView = raw.reinterpret(size, lifetime, seg -> LibC.munmap(seg, size));
        return userView;
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

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void checkBounds(int i) {
        if (i < 0 || i >= maxItems) {
            throw new IndexOutOfBoundsException(
                    "Index " + i + " out of bounds for arena size " + maxItems);
        }
    }

    private long slotOffset(int i) {
        return (long) i * itemStride;
    }

    private MemorySegment sliceAt(int i) {
        return userView().asSlice(slotOffset(i), itemStride);
    }
}
