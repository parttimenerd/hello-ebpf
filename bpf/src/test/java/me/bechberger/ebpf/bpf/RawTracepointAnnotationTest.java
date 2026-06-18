package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.RawTracepoint;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the {@code @RawTracepoint} shorthand annotation generates the correct
 * {@code raw_tracepoint/<name>} section, uses the {@code BPF_PROG} header template,
 * and auto-attaches successfully.
 *
 * <p>{@code sys_enter} fires on every syscall entry with a pointer to pt_regs and the
 * syscall number. After triggering an {@code openat} the {@code triggered} global
 * should flip to {@code true}.
 */
public class RawTracepointAnnotationTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @RawTracepoint("sys_enter")
        void onSysEnter(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long syscallNr) {
            triggered.set(true);
        }
    }

    @Test
    @Timeout(10)
    public void testRawTracepointFires() {
        // Verify the generated C uses the BPF_PROG header, not a plain int function.
        String code = BPFProgram.getCode(Program.class);
        assertTrue(code.contains("BPF_PROG"),
                "raw_tracepoint program must use BPF_PROG header; got:\n" + code);

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.triggered.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.triggered.get(),
                    "@RawTracepoint(sys_enter) should have fired");
        }
    }
}
