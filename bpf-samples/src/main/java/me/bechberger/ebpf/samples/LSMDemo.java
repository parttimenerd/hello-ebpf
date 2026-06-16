package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.LSM;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

/**
 * Demonstrates LSM BPF hooks using the {@code @LSM} annotation.
 *
 * <p>Hooks into three kernel security hooks and prints a trace line for each event:
 * <ul>
 *   <li>{@code file_open} — every file open
 *   <li>{@code bpf} — every BPF syscall
 *   <li>{@code socket_create} — every socket creation
 * </ul>
 *
 * <p>Requires {@code CONFIG_BPF_LSM=y} and {@code lsm=...,bpf} on the kernel command line.
 * Verify with: {@code cat /sys/kernel/security/lsm | grep bpf}
 *
 * <p>Run as root; watch output with: {@code cat /sys/kernel/debug/tracing/trace_pipe}
 */
@BPF(license = "GPL")
public abstract class LSMDemo extends BPFProgram {

    final GlobalVariable<Integer> fileOpenCount = new GlobalVariable<>(0);
    final GlobalVariable<Integer> bpfCallCount = new GlobalVariable<>(0);
    final GlobalVariable<Integer> socketCount = new GlobalVariable<>(0);

    @LSM("file_open")
    int onFileOpen(Ptr<runtime.file> file) {
        fileOpenCount.set(fileOpenCount.get() + 1);
        bpf_trace_printk("LSM file_open #%d", fileOpenCount.get());
        return 0;
    }

    @LSM("bpf")
    int onBpf(int cmd, Ptr<?> attr, int size) {
        bpfCallCount.set(bpfCallCount.get() + 1);
        bpf_trace_printk("LSM bpf cmd=%d #%d", cmd, bpfCallCount.get());
        return 0;
    }

    @LSM("socket_create")
    int onSocketCreate(int family, int type, int protocol, int kern) {
        socketCount.set(socketCount.get() + 1);
        bpf_trace_printk("LSM socket_create family=%d #%d", family, socketCount.get());
        return 0;
    }

    public static void main(String[] args) throws InterruptedException {
        if (!BPFProgram.isLSMEnabled()) {
            System.err.println("WARNING: BPF LSM is not enabled on this kernel.");
            System.err.println("  Verify with: cat /sys/kernel/security/lsm | grep bpf");
            System.err.println("  Enable with: lsm=lockdown,capability,yama,bpf in kernel cmdline");
        }
        try (var program = BPFProgram.load(LSMDemo.class)) {
            program.autoAttachPrograms();
            System.out.println("LSM hooks attached. Monitoring file opens, BPF calls, and socket creations.");
            System.out.println("Press Ctrl-C to stop. Counts update every second.");
            while (true) {
                Thread.sleep(1000);
                System.out.printf("  file_open=%d  bpf=%d  socket_create=%d%n",
                        program.fileOpenCount.get(),
                        program.bpfCallCount.get(),
                        program.socketCount.get());
            }
        }
    }
}
