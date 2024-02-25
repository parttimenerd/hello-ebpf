package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram.BPFProgramNotFound;
import me.bechberger.ebpf.samples.HelloWorld;
import org.junit.jupiter.api.Test;

import java.io.IOException;

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
    public void testProgramLoad() throws IOException {
        try (var program = BPFProgram.load(Prog.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            assertEquals("Hello, World from BPF and more!", program.readTraceFields().msg());
        }
    }

    @Test
    public void testFailingProgramByName() throws IOException {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) {
            assertThrows(BPFProgramNotFound.class, () -> program.getProgramByName("invalid-name"));
        }
    }
}
