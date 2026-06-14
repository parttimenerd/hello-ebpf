package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
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
    public void testTracePrintkAppearsInTraceLog() throws InterruptedException {
        // Drain any stale lines before the test so we don't hit old data.
        TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(50));

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe never fired");

            // Give the trace pipe time to flush; then collect lines.
            Thread.sleep(100);
            List<String> lines = TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(500));

            boolean found = lines.stream().anyMatch(l -> l.contains(MARKER));
            assertTrue(found,
                    "Expected to find '" + MARKER + "' in trace log; got " + lines.size()
                            + " lines:\n" + String.join("\n", lines.subList(0, Math.min(10, lines.size()))));
        }
    }
}
