package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that a {@link BPFRingBuffer} with a typed {@code @Type} record works
 * end-to-end: the BPF program reserves a slot, fills the struct fields, submits it,
 * and user-space receives the record via a ring-buffer callback.
 *
 * <p>Tests:
 * <ul>
 *   <li>Reserve a struct record from BPF side.</li>
 *   <li>Write individual fields via {@code Ptr.of(event.val().field).set(value)}.</li>
 *   <li>Submit the record.</li>
 *   <li>User-side callback receives the record with correct field values.</li>
 * </ul>
 */
public class RingBufferTypedEventTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        record Event(int pid, int count) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFRingBuffer<Event> events;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            Ptr<Event> ev = events.reserve();
            if (ev == null) return 0;

            // Write fields: pid = 42, count = 7.
            Ptr.of(ev.val().pid).set(42);
            Ptr.of(ev.val().count).set(7);
            events.submit(ev);
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testRingBufferTypedEventDelivered() throws InterruptedException {
        AtomicReference<Program.Event> received = new AtomicReference<>();

        try (var program = BPFProgram.load(Program.class)) {
            program.events.setCallback(ev -> received.set(ev));
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe never fired");

            // Drain the ring buffer to invoke the callback.
            try { program.events.consume(); } catch (Exception ignored) {}

            Program.Event ev = received.get();
            assertNotNull(ev, "ring buffer callback should have been called");
            assertEquals(42, ev.pid(), "event.pid should be 42");
            assertEquals(7,  ev.count(), "event.count should be 7");
        }
    }
}
