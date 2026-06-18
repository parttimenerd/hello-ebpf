package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.KFunc;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that the compiler plugin auto-emits {@code __ksym} forward
 * declarations for any {@link KFunc}-annotated method called transitively
 * from a {@code @BPFFunction} entry point.
 *
 * <p>Replaces the prior workaround where each {@code @BPFInterface} had to
 * hand-write the {@code __ksym} decls in its {@code before=} block — see the
 * {@code Scheduler.java} delta where cpumask kfuncs no longer need manual
 * forward declarations.
 */
public class KFuncEmissionTest {

    @BPF
    public static abstract class KFuncProgram extends BPFProgram {

        @BuiltinBPFFunction("fake_kfunc_alpha($arg1)")
        @KFunc(signature = "int fake_kfunc_alpha(int x)")
        @NotUsableInJava
        public static int fakeKfuncAlpha(int x) {
            throw new MethodIsBPFRelatedFunction();
        }

        @BuiltinBPFFunction("fake_kfunc_beta()")
        @KFunc(signature = "void fake_kfunc_beta(void)")
        @NotUsableInJava
        public static void fakeKfuncBeta() {
            throw new MethodIsBPFRelatedFunction();
        }

        @BPFFunction
        public int useAlpha(int x) {
            return fakeKfuncAlpha(x);
        }

        @BPFFunction
        public void useBoth(int x) {
            fakeKfuncBeta();
            fakeKfuncAlpha(x);
        }
    }

    @Test
    public void testKfuncForwardDeclsEmitted() {
        var code = BPFProgram.getCode(KFuncProgram.class);
        assertTrue(code.contains("int fake_kfunc_alpha(int x) __ksym;"),
                "expected alpha __ksym decl in:\n" + code);
        assertTrue(code.contains("void fake_kfunc_beta(void) __ksym;"),
                "expected beta __ksym decl in:\n" + code);

        // The decl for each kfunc should appear exactly once, even though
        // alpha is called from two different @BPFFunctions.
        int alphaCount = code.split("int fake_kfunc_alpha\\(int x\\) __ksym;", -1).length - 1;
        assertTrue(alphaCount == 1, "alpha __ksym decl should appear once, got " + alphaCount + ":\n" + code);
    }

    @BPF
    public static abstract class NoKFuncProgram extends BPFProgram {
        @BPFFunction
        public int trivial() {
            return 42;
        }
    }

    @Test
    public void testNoKfuncsEmitted() {
        var code = BPFProgram.getCode(NoKFuncProgram.class);
        assertTrue(!code.contains("__ksym;"),
                "expected no __ksym decls in trivial program:\n" + code);
    }

    /**
     * End-to-end check that calling a real {@code BpfDefinitions} kfunc
     * (one regenerated with {@code @KFunc} from BTF DECL_TAG) gets a
     * matching {@code __ksym} decl in the emitted prologue.
     */
    @BPF
    public static abstract class RealCpumaskProgram extends BPFProgram {
        @BPFFunction
        public int makeMask() {
            var mask = me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_create();
            return mask == null ? 0 : 1;
        }
    }

    @Test
    public void testRealCpumaskKfuncEmitted() {
        var code = BPFProgram.getCode(RealCpumaskProgram.class);
        assertTrue(code.contains("bpf_cpumask_create") && code.contains("__ksym;"),
                "expected bpf_cpumask_create __ksym decl in:\n" + code);
    }
}
