package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import java.util.function.Consumer;

import static me.bechberger.ebpf.bpf.BPFJ.bpf_trace_printk;

public class MacroTest {

    @BPF
    public static abstract class TestBasicFunctionMacro extends BPFProgram {

        //@BuiltinBPFFunction("$1paramType1 $1param1 = 1; $1code")
        @BuiltinBPFFunction("1")
        public static void testMacro(Consumer<Integer> consumer) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public void code() {
            testMacro((a) -> {
                int x = a;
            });
        }
    }

    @Test
    public void testBasicFunctionMacro() {

    }
}
