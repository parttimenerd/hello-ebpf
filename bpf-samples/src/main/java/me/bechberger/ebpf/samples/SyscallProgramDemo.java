package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.type.Ptr;

/**
 * Demonstrates a {@code SEC("syscall")} BPF program invoked from Java via
 * {@code BPF_PROG_TEST_RUN}.
 *
 * <p>The kernel program reads two integers from a ctx struct, writes their sum
 * into a third field, and returns the sum as the program's int return value.
 * Java fills the ctx, calls {@link BPFProgram#runSyscallProgram(String, Object)},
 * and reads back the kernel-written {@code sum} field.
 *
 * <pre>
 *   sudo ./run.sh SyscallProgramDemo
 * </pre>
 */
@BPF(license = "GPL")
public abstract class SyscallProgramDemo extends BPFProgram {

    @Type
    static class AddCtx {
        int a;
        int b;
        int sum;
    }

    @BPFFunction(
            headerTemplate = "int $name($params)",
            section = "syscall",
            autoAttach = false
    )
    public int add(Ptr<AddCtx> input) {
        int s = input.val().a + input.val().b;
        input.val().sum = s;
        return s;
    }

    public static void main(String[] args) throws Exception {
        try (SyscallProgramDemo program = BPFProgram.load(SyscallProgramDemo.class)) {
            AddCtx ctx = new AddCtx();
            ctx.a = 17;
            ctx.b = 25;
            var result = program.runSyscallProgram("add", ctx);
            System.out.printf("kernel computed %d + %d = %d (retval=%d)%n",
                    ctx.a, ctx.b, result.ctx().sum, result.retval());
        }
    }
}
