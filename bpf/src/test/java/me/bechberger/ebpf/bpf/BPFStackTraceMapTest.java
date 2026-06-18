package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFStackTraceMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for {@link BPFStackTraceMap}.
 *
 * <p>A kprobe on {@code do_sys_openat2} captures the kernel stack trace on each
 * call and stores the stack ID keyed by the calling PID.  The Java side then
 * retrieves and validates the stack frames.
 */
public class BPFStackTraceMapTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1024)
        BPFStackTraceMap stacks;

        @BPFMapDefinition(maxEntries = 256)
        BPFHashMap<Integer, Long> pidToStack;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int captureStack(Ptr<PtDefinitions.pt_regs> ctx) {
            int pid = BPFJ.currentTgid();
            long stackId = stacks.bpf_get_stackid(ctx, 0L);
            if (stackId >= 0) {
                pidToStack.bpf_put(pid, stackId);
            }
            return 0;
        }
    }

    @Test
    @Timeout(15)
    public void testStackTraceCapture() throws Exception {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();

            // Trigger several openat syscalls
            for (int i = 0; i < 3; i++) {
                TestUtil.triggerOpenAt();
            }
            Thread.sleep(200);

            int myPid = (int) ProcessHandle.current().pid();
            Long stackId = program.pidToStack.get(myPid);
            assertNotNull(stackId, "kprobe should have captured stack for PID " + myPid);
            assertTrue(stackId >= 0, "stackId should be non-negative, got " + stackId);

            List<Long> frames = program.stacks.get(stackId.intValue());
            assertFalse(frames.isEmpty(), "stack trace should contain at least one frame");
            assertTrue(frames.stream().allMatch(ip -> ip != 0),
                    "all returned frames should be non-zero instruction pointers");
        }
    }
}
