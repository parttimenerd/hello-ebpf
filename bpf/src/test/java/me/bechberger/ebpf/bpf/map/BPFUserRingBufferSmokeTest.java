package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Smoke test for {@link BPFUserRingBuffer}: verifies that the libbpf
 * {@code user_ring_buffer__new} binding is reachable, that {@code reserve()}
 * returns a non-null segment, and that a {@code reserve}/{@code discard}
 * round-trip does not crash the process.
 *
 * <p>This is a load-side test only — it does not exercise the BPF drain path
 * (covered by Task 2). Its sole purpose is to confirm the Java wrapper around
 * the libbpf bindings works end-to-end at the OS map-creation layer.
 *
 * <p>Requires {@code CAP_SYS_ADMIN} / sudo to load BPF programs.
 */
public class BPFUserRingBufferSmokeTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        record Msg(@Unsigned int pid) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFUserRingBuffer<Msg> outbox;

        // Trivial kprobe so the program is loadable. The BPF side does not
        // interact with the user ring buffer in this smoke test.
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    /**
     * Verify that:
     * <ul>
     *   <li>The program loads with {@code BPF_MAP_TYPE_USER_RINGBUF} without
     *       crashing.</li>
     *   <li>{@code outbox} is non-null and has the expected type.</li>
     *   <li>{@code reserve()} returns a non-null {@link MemorySegment}.</li>
     *   <li>{@code discard()} releases the slot without error.</li>
     *   <li>The program and map close cleanly.</li>
     * </ul>
     */
    @Test
    @Timeout(10)
    public void userRingBufferReserveDiscardRoundTrip() {
        try (var program = BPFProgram.load(Program.class)) {
            BPFUserRingBuffer<Program.Msg> outbox = program.outbox;
            assertNotNull(outbox, "outbox map field should be initialised by the framework");
            assertEquals(MapTypeId.USER_RINGBUF, outbox.getInfo().type(),
                    "kernel should report this as BPF_MAP_TYPE_USER_RINGBUF");

            // Reserve a slot — ring buffer is empty so this must succeed.
            MemorySegment slot = outbox.reserve();
            assertNotNull(slot, "reserve() must return non-null on an empty ring buffer");
            assertTrue(slot.byteSize() > 0,
                    "reserved slot must have a positive size (got " + slot.byteSize() + ")");

            // Write a recognisable sentinel so we can verify the slot is writable.
            slot.set(ValueLayout.JAVA_INT, 0, 0xDEADBEEF);
            assertEquals(0xDEADBEEF, slot.get(ValueLayout.JAVA_INT, 0),
                    "slot must be writable before discard");

            // Discard the slot — no visible side-effect, no crash.
            outbox.discard(slot);
            // Implicit: program.close() via try-with-resources exercises BPFUserRingBuffer.close().
        }
    }
}
