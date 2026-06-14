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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that multiple events can be sent through a {@link BPFRingBuffer} in a
 * single BPF invocation and that all events arrive on the Java side.
 *
 * <p>The kprobe fires once and emits 5 events with sequential counters (0..4).
 * The test verifies:
 * <ul>
 *   <li>All 5 events arrive via the callback.</li>
 *   <li>Events arrive in-order (ring buffer preserves submission order).</li>
 *   <li>Each event carries the expected counter value and a sentinel marker.</li>
 * </ul>
 */
public class RingBufferMultiEventTest {

    static final int NUM_EVENTS = 5;
    static final int SENTINEL = 0xBEEF;

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @Type
        record Event(int seq, int marker) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFRingBuffer<Event> events;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Submit NUM_EVENTS events in sequence.
            for (int i = 0; i < NUM_EVENTS; i++) {
                Ptr<Event> ev = events.reserve();
                if (ev == null) return 0;
                Ptr.of(ev.val().seq).set(i);
                Ptr.of(ev.val().marker).set(SENTINEL);
                events.submit(ev);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testMultipleEventsArrive() throws InterruptedException {
        List<Program.Event> received = new ArrayList<>();

        try (var program = BPFProgram.load(Program.class)) {
            program.events.setCallback(ev -> received.add(ev));
            program.autoAttachPrograms();

            TestUtil.triggerOpenAt();

            // Wait for the kprobe to fire.
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            // Drain the ring buffer.
            try { program.events.consume(); } catch (Exception ignored) {}

            assertEquals(NUM_EVENTS, received.size(),
                    "All " + NUM_EVENTS + " events should have arrived, got " + received.size());

            // Verify in-order delivery and correct payload.
            for (int i = 0; i < NUM_EVENTS; i++) {
                Program.Event ev = received.get(i);
                assertEquals(i, ev.seq(),
                        "Event[" + i + "].seq should be " + i + ", got " + ev.seq());
                assertEquals(SENTINEL, ev.marker(),
                        "Event[" + i + "].marker should be 0x" + Integer.toHexString(SENTINEL));
            }
        }
    }

    /**
     * Verifies that discarded (not-submitted) ring buffer entries are not delivered
     * to the user-space callback.
     */
    @BPF(license = "GPL")
    public static abstract class DiscardProgram extends BPFProgram {

        @Type
        record TaggedEvent(int id, boolean submitted) {}

        @BPFMapDefinition(maxEntries = 4096)
        BPFRingBuffer<TaggedEvent> events;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Reserve and submit event with id=1.
            Ptr<TaggedEvent> ev1 = events.reserve();
            if (ev1 != null) {
                Ptr.of(ev1.val().id).set(1);
                Ptr.of(ev1.val().submitted).set(true);
                events.submit(ev1);
            }

            // Reserve but discard event with id=2.
            Ptr<TaggedEvent> ev2 = events.reserve();
            if (ev2 != null) {
                Ptr.of(ev2.val().id).set(2);
                Ptr.of(ev2.val().submitted).set(false);
                events.discard(ev2);
            }

            // Reserve and submit event with id=3.
            Ptr<TaggedEvent> ev3 = events.reserve();
            if (ev3 != null) {
                Ptr.of(ev3.val().id).set(3);
                Ptr.of(ev3.val().submitted).set(true);
                events.submit(ev3);
            }

            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testDiscardedEntryNotDelivered() throws InterruptedException {
        List<DiscardProgram.TaggedEvent> received = new ArrayList<>();

        try (var program = BPFProgram.load(DiscardProgram.class)) {
            program.events.setCallback(ev -> received.add(ev));
            program.autoAttachPrograms();

            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            try { program.events.consume(); } catch (Exception ignored) {}

            // Only events 1 and 3 should arrive; event 2 was discarded.
            assertEquals(2, received.size(),
                    "Only 2 submitted events should arrive (not the discarded one)");
            assertEquals(1, received.get(0).id(), "First event should have id=1");
            assertTrue(received.get(0).submitted(), "First event should be marked submitted");
            assertEquals(3, received.get(1).id(), "Second event should have id=3");
            assertTrue(received.get(1).submitted(), "Second event should be marked submitted");
        }
    }
}
