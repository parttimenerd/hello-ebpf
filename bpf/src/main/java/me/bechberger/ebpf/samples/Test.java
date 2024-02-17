/*
 * Hello, World from BPF
 */
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.samples.test.TestProgramImpl;

public class Test {
    @BPF
    public static abstract class TestProgram extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                
                SEC ("kprobe/do_sys_openat2") int kprobe__do_sys_openat2 (struct pt_regs *ctx){                                                                   
                    bpf_printk("Hello, World from BPF and more!\\n");
                    return 0;
                }
                
                char _license[] SEC ("license") = "GPL";
                """;
    }

    public static void main(String[] args) {
        try (TestProgram program = new TestProgramImpl()) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            program.tracePrintLoop();
        }
    }
}