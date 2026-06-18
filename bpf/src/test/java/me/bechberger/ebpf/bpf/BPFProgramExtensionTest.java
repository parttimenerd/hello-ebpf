package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link BPFProgramExtension} / {@link TestBPFProgram}.
 */
@ExtendWith(BPFProgramExtension.class)
public class BPFProgramExtensionTest {

    @BPF(license = "GPL")
    public static abstract class Prog extends BPFProgram {
        final GlobalVariable<Boolean> triggered = new GlobalVariable<>(false);

        @BPFFunction(section = "fentry/do_sys_openat2", autoAttach = true)
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            triggered.set(true);
            return 0;
        }
    }

    /** Extension loads, auto-attaches, injects, and closes the program. */
    @Test
    @Timeout(5)
    @TestBPFProgram(Prog.class)
    void testExtensionLoadsAndAutoAttaches(Prog program) {
        TestUtil.triggerOpenAt();
        assertTrue(program.triggered.get(), "BPF probe should have fired");
    }

    /** autoAttach=false: extension loads but does not attach. */
    @Test
    @Timeout(5)
    @TestBPFProgram(value = Prog.class, autoAttach = false)
    void testExtensionWithoutAutoAttach(Prog program) {
        // program is loaded but not yet attached — manual attach
        program.autoAttachPrograms();
        TestUtil.triggerOpenAt();
        assertTrue(program.triggered.get(), "BPF probe should have fired after manual attach");
    }
}
