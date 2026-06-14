package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFProgArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for BPF tail calls using {@link BPFProgArray}.
 *
 * <p>Two kprobe-triggered sub-programs are registered in a prog array:
 * <ul>
 *   <li>Slot 0 ("increment"): increments a counter global and stores its result index.</li>
 *   <li>Slot 1 ("double"):    doubles the running counter value.</li>
 * </ul>
 * The main entry program dispatches to one of these sub-programs via a tail call
 * depending on the current invocation count (stored in a global).
 */
public class TailCallTest {

    static final int SLOT_INCREMENT = 0;
    static final int SLOT_DOUBLE = 1;

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 2)
        BPFProgArray progs;

        /** Counts how many times the main entry has been invoked. */
        final GlobalVariable<Integer> invocations = new GlobalVariable<>(0);

        /** Stores results: index 0 = value after increment tail-call, index 1 = value after double tail-call. */
        @BPFMapDefinition(maxEntries = 4)
        BPFArray<Integer> results;

        /** Set to true after both sub-programs ran. */
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        /** Sub-program 0: stored in slot SLOT_INCREMENT. Stores current invocations count. */
        @BPFFunction(section = "kprobe/do_sys_openat2")
        int incrementHandler(Ptr<PtDefinitions.pt_regs> ctx) {
            results.put(0, invocations.get());
            return 0;
        }

        /** Sub-program 1: stored in slot SLOT_DOUBLE. Doubles results[0] and stores in results[1]. */
        @BPFFunction(section = "kprobe/do_sys_openat2")
        int doubleHandler(Ptr<PtDefinitions.pt_regs> ctx) {
            Ptr<Integer> v = results.bpf_get(0);
            if (v != null) {
                results.put(1, v.val() * 2);
            }
            done.set(true);
            return 0;
        }

        /** Main entry: on first call tail-calls slot 0, on second call tail-calls slot 1. */
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            int n = invocations.get();
            invocations.set(n + 1);
            if (n == 0) {
                // First open: tail-call increment
                progs.tailCall(ctx, SLOT_INCREMENT);
            } else if (n == 1) {
                // Second open: tail-call double
                progs.tailCall(ctx, SLOT_DOUBLE);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testTailCallIncrementAndDouble() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            // Register sub-programs before attaching.
            program.progs.register(SLOT_INCREMENT, program.getProgramByName("incrementHandler"));
            program.progs.register(SLOT_DOUBLE, program.getProgramByName("doubleHandler"));

            program.autoAttachPrograms();

            // First trigger: should tail-call incrementHandler → results[0] = 1
            TestUtil.triggerOpenAt();
            // Poll until invocations >= 1
            long deadline = System.currentTimeMillis() + 5000;
            while (program.invocations.get() < 1 && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.invocations.get() >= 1, "First kprobe should have fired");

            // Give the tail-call a moment to run
            Thread.sleep(50);
            assertEquals(1, program.results.get(0).intValue(),
                    "After increment tail-call, results[0] should be 1");

            // Second trigger: should tail-call doubleHandler → results[1] = 2, done = true
            TestUtil.triggerOpenAt();
            deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "doubleHandler tail-call should have set done=true");
            assertEquals(2, program.results.get(1).intValue(),
                    "After double tail-call, results[1] should be 2 (1 * 2)");
        }
    }

    /**
     * Verifies that registering and re-registering a slot works correctly (slot can be overwritten).
     */
    @Test
    @Timeout(10)
    public void testProgArrayRegistration() {
        try (var program = BPFProgram.load(Program.class)) {
            // Just verify that the prog array can be loaded and slots registered.
            var progs = program.progs;
            assertNotNull(progs, "prog array should be non-null");
            assertEquals(2, progs.getMaxEntries(), "prog array should have 2 slots");

            // Register both slots; overwrite slot 0 with the double handler
            progs.register(SLOT_INCREMENT, program.getProgramByName("incrementHandler"));
            progs.register(SLOT_DOUBLE, program.getProgramByName("doubleHandler"));
            // Overwrite slot 0 with double handler — should not throw
            progs.register(SLOT_INCREMENT, program.getProgramByName("doubleHandler"));
        }
    }

    /**
     * Verifies that registering an out-of-bounds slot throws an exception.
     */
    @Test
    public void testProgArrayOutOfBoundsThrows() {
        try (var program = BPFProgram.load(Program.class)) {
            var progs = program.progs;
            assertThrows(BPFError.class,
                    () -> progs.register(99, program.getProgramByName("incrementHandler")),
                    "Registering at slot 99 (max_entries=2) should throw BPFError");
        }
    }
}
