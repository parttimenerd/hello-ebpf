package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

/**
 * Logs all openat2 calls
 */
@BPF(license = "GPL")
public abstract class LogOpenAt2Calls extends BPFProgram implements SystemCallHooks {

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        open_how copy = new open_how();
        BPFJ.bpf_probe_read_kernel(copy, how);
        bpf_trace_printk("Accessed file %s: flags=%d, mode=%d", filename, copy.flags, copy.mode);
    }

    public static void main(String[] args) {
        try (LogOpenAt2Calls program = BPFProgram.load(LogOpenAt2Calls.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoop(f -> String.format("%d: %s: %s", (int)f.ts(), f.task(), f.msg()));
        }
    }
}