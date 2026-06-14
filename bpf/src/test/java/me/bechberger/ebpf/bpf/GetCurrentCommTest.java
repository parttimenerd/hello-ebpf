package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that {@link BPFJ#getCurrentComm(char[])} reads the current process's
 * task name into a BPF stack buffer, and that the value is non-empty and reasonable.
 *
 * <p>The kprobe captures the comm of the process that triggered the open (the JVM
 * test runner). It stores the first two bytes into a global array so user-space can
 * inspect them without needing a ring buffer.
 */
public class GetCurrentCommTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        /**
         * Stores the first character of the comm (as int) at index 0, and the length
         * (number of non-zero bytes up to 16) at index 1.
         */
        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> result;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) char[] comm = BPFJ.charBuf(16);
            BPFJ.getCurrentComm(comm);

            // Store first character (as int) at index 0.
            int first = comm[0];
            result.put(0, first);

            // Count non-zero chars (up to TASK_COMM_LEN = 16) and store at index 1.
            int len = 0;
            for (int i = 0; i < 16; i++) {
                if (comm[i] == 0) break;
                len++;
            }
            result.put(1, len);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testGetCurrentCommIsNonEmpty() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                try { Thread.sleep(10); } catch (InterruptedException ignored) {}
            }
            assertTrue(program.done.get(), "kprobe never fired");

            int firstChar = program.result.get(0);
            int len = program.result.get(1);

            assertTrue(firstChar > 0, "first character of comm should be non-zero (got " + firstChar + ")");
            assertTrue(len >= 1 && len <= 16,
                    "comm length should be 1-16 chars, got " + len);
        }
    }
}
