package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link BPFJ#bpf_snprintf} formats a string into a BPF stack
 * buffer and that the formatted bytes reach user-space correctly.
 *
 * <p>{@code BPF_SNPRINTF(out, sizeof(out), fmt, args...)} writes formatted text
 * into {@code out}. This test formats {@code "val=%d"} with the integer {@code 7},
 * then stores the first 8 characters into a global array so user-space can verify
 * the bytes match {@code "val=7"}.
 */
public class BpfSnprintfTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        /** Stores the first {@code N} characters of the formatted string. */
        @BPFMapDefinition(maxEntries = 8)
        BPFArray<Integer> chars;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) String out = "";
            BPFJ.bpf_snprintf(out, "val=%d", 7);

            // Store first 5 character codes so user-space can verify "val=7".
            for (int i = 0; i < 5; i++) {
                chars.put(i, (int) out.charAt(i));
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testBpfSnprintfFormatsCorrectly() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");

            // "val=7" → expected char codes v=118, a=97, l=108, '='=61, '7'=55
            String expected = "val=7";
            for (int i = 0; i < expected.length(); i++) {
                int ch = program.chars.get(i);
                assertEquals((int) expected.charAt(i), ch,
                        "char[" + i + "] should be '" + expected.charAt(i) + "' (" + (int)expected.charAt(i) + "), got " + ch);
            }
        }
    }
}
