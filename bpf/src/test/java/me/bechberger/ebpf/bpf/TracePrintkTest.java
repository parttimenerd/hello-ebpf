package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.Constants;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@link BPFJ#bpf_trace_printk} actually produces output on the
 * kernel trace pipe and that the output is readable via {@link TraceLog}.
 *
 * <p>The BPF program emits a sentinel string that contains a unique marker;
 * after triggering the open, the test drains the trace pipe and asserts at
 * least one line contains the marker.
 */
public class TracePrintkTest {

    private static final String MARKER = "bpf_trace_test_marker_7x9z";

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            bpf_trace_printk(MARKER);
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testTracePrintkAppearsInTraceLog() throws InterruptedException, IOException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe never fired");

            // Give the kernel time to flush bpf_trace_printk output to the trace buffer.
            Thread.sleep(200);

            // Read from the static 'trace' snapshot file — reliable in virtme-ng unlike trace_pipe.
            List<String> lines = Files.readAllLines(Constants.TRACEFS.resolve("trace"));

            boolean found = lines.stream().anyMatch(l -> l.contains(MARKER));
            assertTrue(found,
                    "Expected to find '" + MARKER + "' in trace log; got " + lines.size()
                            + " lines:\n" + String.join("\n", lines.subList(0, Math.min(10, lines.size()))));
        }
    }
}
