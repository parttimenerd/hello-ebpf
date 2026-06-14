package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFTypedArena;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the {@link BPFTypedArena} user-side API:
 * <ul>
 *   <li>Typed {@link BPFTypedArena#get}/{@link BPFTypedArena#set} round-trip</li>
 *   <li>{@link BPFTypedArena#fieldOffset(String)} lookup</li>
 *   <li>Atomic helpers: {@link BPFTypedArena#atomicGetAndAdd},
 *       {@link BPFTypedArena#atomicCompareAndSet},
 *       {@link BPFTypedArena#atomicGetLong}, {@link BPFTypedArena#atomicSetLong}</li>
 *   <li>Bounds checking: out-of-range access throws {@link IndexOutOfBoundsException}</li>
 * </ul>
 */
public class BPFTypedArenaTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        record Slot(int id, long value) {}

        @BPFMapDefinition(maxEntries = 4)
        BPFTypedArena<Slot> arena;

        // Trivial kprobe so the program is loadable.
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testGetSetRoundTrip() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            var arena = program.arena;

            assertEquals(4, arena.size(), "arena should have 4 slots");

            // Write and read back each slot
            for (int i = 0; i < 4; i++) {
                arena.set(i, new Program.Slot(i * 10, (long) i * 1_000_000L));
            }
            for (int i = 0; i < 4; i++) {
                var slot = arena.get(i);
                assertEquals(i * 10, slot.id(), "slot[" + i + "].id mismatch");
                assertEquals((long) i * 1_000_000L, slot.value(), "slot[" + i + "].value mismatch");
            }
        }
    }

    @Test
    @Timeout(10)
    public void testFieldOffset() {
        try (var program = BPFProgram.load(Program.class)) {
            var arena = program.arena;

            // 'id' is the first field (int, 4 bytes) so offset 0
            long idOff = arena.fieldOffset("id");
            assertEquals(0L, idOff, "field 'id' should be at offset 0");

            // 'value' is a long; after 4-byte int the long is 8-byte-aligned → offset 8
            long valueOff = arena.fieldOffset("value");
            assertTrue(valueOff >= 4L, "field 'value' should be after 'id'");
            assertEquals(0L, valueOff % 8L, "field 'value' must be 8-byte-aligned for atomic helpers");

            // Non-existent field throws
            assertThrows(IllegalArgumentException.class, () -> arena.fieldOffset("nonexistent"));
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicGetAndAdd() {
        try (var program = BPFProgram.load(Program.class)) {
            var arena = program.arena;
            long off = arena.fieldOffset("value");

            arena.set(0, new Program.Slot(1, 100L));

            long prev = arena.atomicGetAndAdd(0, off, 7L);
            assertEquals(100L, prev, "atomicGetAndAdd should return previous value");
            assertEquals(107L, arena.get(0).value(), "value should be incremented by 7");
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicCompareAndSet() {
        try (var program = BPFProgram.load(Program.class)) {
            var arena = program.arena;
            long off = arena.fieldOffset("value");

            arena.set(0, new Program.Slot(1, 42L));

            // Successful CAS
            boolean swapped = arena.atomicCompareAndSet(0, off, 42L, 99L);
            assertTrue(swapped, "CAS should succeed when expected matches");
            assertEquals(99L, arena.get(0).value(), "value should be 99 after successful CAS");

            // Failing CAS (wrong expected value)
            boolean notSwapped = arena.atomicCompareAndSet(0, off, 42L, 200L);
            assertFalse(notSwapped, "CAS should fail when expected does not match");
            assertEquals(99L, arena.get(0).value(), "value should remain 99 after failed CAS");
        }
    }

    @Test
    @Timeout(10)
    public void testAtomicGetSetLong() {
        try (var program = BPFProgram.load(Program.class)) {
            var arena = program.arena;
            long off = arena.fieldOffset("value");

            arena.set(0, new Program.Slot(1, 0L));
            arena.atomicSetLong(0, off, 12345L);
            assertEquals(12345L, arena.atomicGetLong(0, off), "atomicGetLong should reflect atomicSetLong");
        }
    }

    @Test
    @Timeout(10)
    public void testBoundsCheck() {
        try (var program = BPFProgram.load(Program.class)) {
            var arena = program.arena;

            assertThrows(IndexOutOfBoundsException.class, () -> arena.get(-1),
                    "get(-1) must throw");
            assertThrows(IndexOutOfBoundsException.class, () -> arena.get(4),
                    "get(size) must throw");
            assertThrows(IndexOutOfBoundsException.class,
                    () -> arena.set(4, new Program.Slot(0, 0L)),
                    "set(size, ...) must throw");
        }
    }

    @Test
    @Timeout(10)
    public void testConstructorGuardZeroMaxItems() {
        // BPFTypedArena requires maxItems > 0; we can't construct it in user-space
        // without a file descriptor, but we can verify size bytes logic indirectly via
        // the loaded program — 4 slots should be > 0.
        try (var program = BPFProgram.load(Program.class)) {
            assertTrue(program.arena.sizeBytes() > 0, "sizeBytes must be positive");
            assertTrue(program.arena.sizeBytes() % BPFTypedArena.PAGE_SIZE == 0,
                    "sizeBytes must be a multiple of PAGE_SIZE");
        }
    }
}
