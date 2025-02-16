package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.sync_fetch_and_add;

/**
 * Counts the total number of syscalls in 5 seconds
 */
@BPF(license = "GPL")
public abstract class SyscallCounter extends BPFProgram {

    final GlobalVariable<Long> syscallCounter = new GlobalVariable<>(0L);

    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, struct pt_regs *regs, unsigned long number)",
            lastStatement = "return 0;",
            section = "raw_tracepoint/sys_enter",
            autoAttach = true
    )
    public void syscall_counter(Ptr<PtDefinitions.pt_regs> regs, @Unsigned long number) {
        sync_fetch_and_add(Ptr.of(syscallCounter.get()), 1);
    }

    public static void main(String[] args) throws InterruptedException {
        try (SyscallCounter program = BPFProgram.load(SyscallCounter.class)) {
            program.rawTracepointAttach("syscall_counter", "sys_enter");
            Thread.sleep(5000);
            System.out.println("There have been " + program.syscallCounter.get() + " syscalls in the last 5 seconds");
        }
    }
}