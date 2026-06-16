package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end test for {@link BPFProgram#runSyscallProgram(String, Object)}: a {@code SEC("syscall")}
 * BPF program that adds two ints from a ctx struct, writes the sum back, and returns the sum.
 */
public class SyscallProgramTest {

    @BPF(license = "GPL")
    public static abstract class Prog extends BPFProgram {

        @Type
        public static class AddCtx {
            public int a;
            public int b;
            public int sum;
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
    }

    @Test
    @Timeout(5)
    public void testSyscallProgramReturnsSum() {
        try (var program = BPFProgram.load(Prog.class)) {
            Prog.AddCtx ctx = new Prog.AddCtx();
            ctx.a = 17;
            ctx.b = 25;
            var result = program.runSyscallProgram("add", ctx);
            assertEquals(42, result.retval(), "kernel program return value");
            assertEquals(42, result.ctx().sum, "kernel-written sum field");
            assertEquals(17, result.ctx().a, "input field a should be preserved");
            assertEquals(25, result.ctx().b, "input field b should be preserved");
        }
    }
}
