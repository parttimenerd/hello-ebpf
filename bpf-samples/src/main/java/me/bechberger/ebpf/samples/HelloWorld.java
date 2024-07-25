package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.OpenDefinitions.open_how;
import me.bechberger.ebpf.runtime.interfaces.SystemCallHooks;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_current_pid_tgid;

/**
 * Hello, World from BPF
 */
@BPF(license = "GPL")
public abstract class HelloWorld extends BPFProgram {

    @BPFFunction(
            headerTemplate = "int BPF_KPROBE($name, int dirfd, const char* pathname, struct open_how* how)",
            lastStatement = "return 0;",
            section = "kprobe/do_sys_openat2",
            autoAttach = true
    )
    public void enterOpenAt2(int dirfd, String pathname, Ptr<open_how> how) {
        BPFJ.bpf_trace_printk("Hello, World from BPF23 and more! %s", pathname);
    }
// TODO: get signature from BTF
    @BPFFunction(
            headerTemplate = "int BPF_PROG($name, int dirfd, const char* pathname, struct open_how* how)",
            lastStatement = "return 0;",
            section = "fentry/do_sys_openat2",
            autoAttach = true
    )
    public void fenterOpenAt2(int dirfd, String pathname, Ptr<open_how> how) {
        BPFJ.bpf_trace_printk("Hello, World from BPF232 and more! %s size %d", pathname);
    }

    /*@BPFFunction(
            headerTemplate = "int kprobe__do_sys_openat2(struct pt_regs *ctx)",
            lastStatement = "return 0;",
            section = "kprobe/do_sys_openat2",
            autoAttach = true,
            name = "kprobe__do_sys_openat2"
    )
    public void enterOpenAt2(int dirfd, String pathname, Ptr<open_how> how, @Unsigned long size) {
        BPFJ.bpf_trace_printk("Hello, World from BPF334 and more!");
    }*/

    /*private static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>
            #include <bpf/bpf_tracing.h>

            SEC("kprobe/do_sys_openat2")
            int kprobe__do_sys_openat2(struct pt_regs *ctx) {
              bpf_trace_printk("Hello, World from BPF3 and more!\\\\n", 35);
              return 0;
            }
            """;*/

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) {
            program.autoAttachPrograms();
            program.tracePrintLoop(f -> String.format("%d: %s: %s", (int)f.ts(), f.task(), f.msg()));
        }
    }
}