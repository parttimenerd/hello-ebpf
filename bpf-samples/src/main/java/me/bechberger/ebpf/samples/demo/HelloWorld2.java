package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

/**
 * Log "Hello, World!" when openat2 is called
 */
@BPF(license = "GPL")
public abstract class HelloWorld2 extends BPFProgram implements SystemCallHooks {

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        bpf_trace_printk("Hello, World!");
    }

    public static void main(String[] args) {
        try (HelloWorld2 program = BPFProgram.load(HelloWorld2.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoop();
        }
    }
}