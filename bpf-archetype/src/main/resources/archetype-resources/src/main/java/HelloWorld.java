package ${package};

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

/**
 * A minimal BPF program that prints "Hello, World!" for every openat2 syscall.
 *
 * <p>Run with: {@code sudo java -jar target/${artifactId}.jar}
 * <p>Then in another terminal: {@code cat /sys/kernel/debug/tracing/trace_pipe}
 */
@BPF(license = "GPL")
public abstract class HelloWorld extends BPFProgram implements SystemCallHooks {

    @Override
    public void enterOpenat2(int dfd, String filename, Ptr<open_how> how) {
        bpf_trace_printk("Hello, World!");
    }

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoop(f -> String.format("%d: %s: %s", (int) f.ts(), f.task(), f.msg()));
        }
    }
}
