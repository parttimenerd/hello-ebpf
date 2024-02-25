/*
 * Hello, World from BPF
 */
package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;

@BPF
public abstract class HelloWorld extends BPFProgram {

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

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            program.tracePrintLoop(f -> String.format("%d: %s: %s", (int)f.ts(), f.task(), f.msg()));
        }
    }
}