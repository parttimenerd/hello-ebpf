package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BPFUserRingBuffer}: reserve/submit/discard cycles,
 * full-buffer behaviour, and close cleanup.
 *
 * <p>The BPF consumer side is driven by a {@code SEC("syscall")} program
 * invoked via {@link BPFProgram#runSyscallProgram(String, Object)}, following
 * the pattern established by {@code BPFRingBufferConsumeRawTest}.
 *
 * <p>Requires {@code CAP_SYS_ADMIN} / sudo to load BPF programs.
 */
public class BPFUserRingBufferTest {

    @BPF(license = "GPL")
    public static abstract class Consumer extends BPFProgram {

        /** Record written by user space and read by the BPF drain program. */
        @Type
        record Msg(@Unsigned int pid, @Unsigned long ts) {}

        /** No-arg context for {@code drainOnce}: nothing needs to be passed in or out. */
        @Type
        public static class DrainCtx {
            public int drained;
        }

        @BPFMapDefinition(maxEntries = 4096)
        public BPFUserRingBuffer<Msg> rb;

        /** Number of records consumed so far, incremented by each drain callback. */
        public final GlobalVariable<@Unsigned Long> seen = new GlobalVariable<>(0L);

        /**
         * Drain all pending records from the user ring buffer and update {@code seen}.
         * Declared with {@code section = "syscall"} so it can be invoked from Java
         * via {@link BPFProgram#runSyscallProgram(String, Object)}.
         */
        @BPFFunction(
                headerTemplate = "int $name($params)",
                section = "syscall",
                autoAttach = false
        )
        public int drainOnce(Ptr<DrainCtx> ctx) {
            DrainCtx local = new DrainCtx();
            Ptr<DrainCtx> lp = Ptr.of(local);
            int n = rb.drain((m, c) -> {
                seen.set(seen.get() + 1);
                return 0;
            }, lp);
            if (ctx != null) {
                ctx.val().drained = n;
            }
            return n;
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Write a {@code Msg(pid, ts)} into a reserved slot.
     *
     * <p>Layout of {@code Msg}: 4 bytes {@code pid} at offset 0, 4 bytes
     * padding, 8 bytes {@code ts} at offset 8 (standard C alignment rules for
     * a struct with an {@code int} followed by a {@code long}).
     */
    private static void writeMsg(MemorySegment slot, int pid, long ts) {
        slot.set(ValueLayout.JAVA_INT, 0, pid);
        slot.set(ValueLayout.JAVA_LONG, 8, ts);
    }

    /** Invoke {@code drainOnce} via BPF_PROG_TEST_RUN and return records drained. */
    private static int callDrainOnce(Consumer p) {
        Consumer.DrainCtx ctx = new Consumer.DrainCtx();
        var result = p.runSyscallProgram("drainOnce", ctx);
        return result.retval();
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    /**
     * Reserve a slot, write a {@code Msg(pid=1234, ts=5678)}, submit, trigger
     * the BPF drain, then verify the {@code seen} counter reaches 1.
     */
    @Test
    @Timeout(10)
    public void testReserveSubmitDrain() {
        try (var p = BPFProgram.load(Consumer.class)) {
            MemorySegment slot = p.rb.reserve();
            assertNotNull(slot, "reserve() must succeed on an empty ring buffer");

            writeMsg(slot, 1234, 5678L);
            p.rb.submit(slot);

            int drained = callDrainOnce(p);
            assertTrue(drained >= 1, "drainOnce must report at least 1 record drained, got " + drained);

            long seenCount = p.seen.get();
            assertEquals(1L, seenCount,
                    "seen counter must be 1 after draining one submitted record, got " + seenCount);
        }
    }

    /**
     * Loop calling {@code reserve()} without submitting or discarding until
     * it returns {@code null}, proving the buffer fills up.  The loop is
     * capped at 100_000 iterations to catch infinite-loop bugs.
     */
    @Test
    @Timeout(10)
    public void testReserveReturnsNullWhenFull() {
        try (var p = BPFProgram.load(Consumer.class)) {
            int reserved = 0;
            final int CAP = 100_000;
            for (int i = 0; i < CAP; i++) {
                MemorySegment slot = p.rb.reserve();
                if (slot == null) {
                    break;
                }
                reserved++;
            }
            assertTrue(reserved > 0,
                    "at least one slot must be reservable on a fresh ring buffer");
            assertNull(p.rb.reserve(),
                    "reserve() must return null once the buffer is full");
        }
    }

    /**
     * Reserve a slot, discard it, then verify a fresh reserve still succeeds
     * (the discarded slot was returned to the pool).
     */
    @Test
    @Timeout(10)
    public void testDiscardReleasesSlot() {
        try (var p = BPFProgram.load(Consumer.class)) {
            MemorySegment first = p.rb.reserve();
            assertNotNull(first, "first reserve() must succeed on an empty ring buffer");

            p.rb.discard(first);

            MemorySegment second = p.rb.reserve();
            assertNotNull(second,
                    "reserve() after discard() must succeed — discarded slot must be returned to the pool");

            // Clean up — discard the second slot so the buffer is fully released.
            p.rb.discard(second);
        }
    }
}
