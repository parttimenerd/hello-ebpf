package me.bechberger.ebpf.samples.demo;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

/**
 * Hello, World from BPF
 */
@BPF(license = "GPL")
public abstract class Sample extends BPFProgram implements SystemCallHooks {

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<OpenDefinitions.open_how> how) {
        BPFJ.bpf_trace_printk("Hi file %s", filename);
    }

    public static void main(String[] args) {
        try (BPFProgram program = BPFProgram.load(Sample.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoopCleaned();
        }
    }
}