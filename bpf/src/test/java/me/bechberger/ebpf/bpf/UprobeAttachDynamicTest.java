package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link BPFProgram#attachUprobe} and {@link BPFProgram#attachUretprobe}
 * attach and fire user-space probes dynamically at runtime.
 *
 * <p>Uses {@code malloc} in libc as the probe target — it is called implicitly by the
 * JVM on every heap allocation, so it fires quickly without any explicit trigger.
 */
public class UprobeAttachDynamicTest {

    static final String LIBC = "/lib/x86_64-linux-gnu/libc.so.6";

    @BPF(license = "GPL")
    public static abstract class UprobeProgram extends BPFProgram {
        final GlobalVariable<Integer> uprobeCount = new GlobalVariable<>(0);

        @BPFFunction(section = "uprobe/malloc", autoAttach = false)
        int onMalloc(Ptr<PtDefinitions.pt_regs> ctx) {
            uprobeCount.set(uprobeCount.get() + 1);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class UretprobeProgram extends BPFProgram {
        final GlobalVariable<Integer> uretprobeCount = new GlobalVariable<>(0);

        @BPFFunction(section = "uretprobe/malloc", autoAttach = false)
        int onMallocReturn(Ptr<PtDefinitions.pt_regs> ctx) {
            uretprobeCount.set(uretprobeCount.get() + 1);
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testUprobeDynamicAttach() throws Exception {
        try (var program = BPFProgram.load(UprobeProgram.class)) {
            program.attachUprobe(
                    program.getProgramByName("onMalloc"), LIBC, "malloc");
            long deadline = System.currentTimeMillis() + 5000;
            while (program.uprobeCount.get() == 0 && System.currentTimeMillis() < deadline) {
                // JVM heap allocations will trigger malloc in libc
                @SuppressWarnings("unused") byte[] dummy = new byte[64];
                Thread.sleep(10);
            }
            assertTrue(program.uprobeCount.get() > 0,
                    "dynamic uprobe on malloc should have fired at least once");
        }
    }

    @Test
    @Timeout(15)
    public void testUretprobeDynamicAttach() throws Exception {
        try (var program = BPFProgram.load(UretprobeProgram.class)) {
            program.attachUretprobe(
                    program.getProgramByName("onMallocReturn"), LIBC, "malloc");
            long deadline = System.currentTimeMillis() + 5000;
            while (program.uretprobeCount.get() == 0 && System.currentTimeMillis() < deadline) {
                @SuppressWarnings("unused") byte[] dummy = new byte[64];
                Thread.sleep(10);
            }
            assertTrue(program.uretprobeCount.get() > 0,
                    "dynamic uretprobe on malloc should have fired at least once");
        }
    }
}
