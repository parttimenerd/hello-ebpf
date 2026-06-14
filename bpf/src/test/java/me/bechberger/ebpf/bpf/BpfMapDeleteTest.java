package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@code bpf_delete} (i.e. {@code bpf_map_delete_elem}) works
 * correctly when called from a {@code @BPFFunction}-annotated probe.
 * The kprobe removes a key that was pre-inserted from user-space; afterwards
 * user-space asserts the key is gone.
 */
public class BpfMapDeleteTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Integer> map;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            // Delete key 42 that user-space seeded before firing the probe
            map.bpf_delete(42);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfDeleteRemovesEntry() {
        try (var program = BPFProgram.load(Program.class)) {
            // Pre-seed before attaching so the kprobe sees the value on first fire.
            program.map.put(42, 100);
            program.map.put(99, 200);

            assertTrue(program.map.containsKey(42), "key 42 must exist before probe fires");

            program.autoAttachPrograms();

            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");

            assertFalse(program.map.containsKey(42),
                    "bpf_delete(42) in kprobe must remove key 42");
            assertTrue(program.map.containsKey(99),
                    "key 99 must remain after bpf_delete(42)");
            assertEquals(200, program.map.get(99).intValue(),
                    "key 99's value must be unchanged");
        }
    }
}
