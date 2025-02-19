package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram.BPFProgramNotFound;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests a simple compile, load and attach
 */
public class HelloWorldTest {

    @BPF(license = "GPL")
    public static abstract class Prog extends BPFProgram {
        final GlobalVariable<Boolean> hello = new GlobalVariable<>(false);

        @BPFFunction(
                section = "fentry/do_sys_openat2",
                autoAttach = true
        )
        int helloWorld(Ptr<PtDefinitions.pt_regs> ctx) {
            hello.set(true);
            return 0;
        }
    }

    @Test
    @Timeout(5)
    public void testProgramLoad() {
        try (var program = BPFProgram.load(Prog.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();
            assertTrue(program.hello.get());
        }
    }

    @Test
    public void testFailingProgramByName() {
        try (var program = BPFProgram.load(Prog.class)) {
            assertThrows(BPFProgramNotFound.class, () -> program.getProgramByName("invalid-name"));
        }
    }

    /**
     * Test the program is properly closed after
     */
    @Test
    public void testProgramClose() {
        try (var program = BPFProgram.load(Prog.class)) {
            var attached = program.autoAttachProgram(program.getProgramByName("helloWorld"));
            program.detachProgram(attached);
            program.hello.set(false);
            TestUtil.triggerOpenAt();

            long start = System.currentTimeMillis();
            // run for 20ms
            while (System.currentTimeMillis() - start < 20) {
                assertFalse(program.hello.get());
            }
        }
    }
}
