package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram.BPFProgramNotFound;
import me.bechberger.ebpf.samples.HelloWorld;
import me.bechberger.ebpf.shared.TraceLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests a simple compile, load and attach
 */
public class HelloWorldTest {

    @BPF
    public static abstract class Prog extends BPFProgram {
        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                                
                SEC ("kprobe/do_sys_openat2")
                int kprobe__do_sys_openat2(struct pt_regs *ctx){
                    bpf_printk("Hello, World from BPF and more!");
                    return 0;
                }
                        
                char _license[] SEC ("license") = "GPL";
                """;
    }

    @Test
    @Timeout(5)
    public void testProgramLoad() {
        try (var program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            while (true) {
                if (program.readTraceFields().msg().equals("Hello, World from BPF and more!")) {
                    break;
                }
            }
        }
    }

    @Test
    public void testFailingProgramByName() {
        try (var program = BPFProgram.load(Prog.class)) {
            assertThrows(BPFProgramNotFound.class, () -> program.getProgramByName("invalid-name"));
        }
    }

    // Test the program is properly closed after
    // by running two programs after another (only the first prints), the second reads, or maybe one program is enough

    /**
     * Test the program is properly closed after
     */
    @Test
    public void testProgramClose() {
        try (var program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
        }
        TestUtil.triggerOpenAt();
        // run for 20ms
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < 20) {
            assertNull(TraceLog.getInstance().readLineIfPossible());
        }
    }
}
