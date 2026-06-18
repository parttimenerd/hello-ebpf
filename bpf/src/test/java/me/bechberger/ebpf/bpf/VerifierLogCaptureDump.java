package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import java.util.List;

/**
 * Captures real verifier-rejection logs from the kernel and prints them so we can paste
 * them into unit-test fixtures. Runs the same programs as
 * {@link RealVerifierClassificationTest} but only for capture purposes — the assertion
 * is that the log is non-empty.
 *
 * <p>To dump logs to stdout, run with {@code -Dtest=VerifierLogCaptureDump}.</p>
 */
public class VerifierLogCaptureDump {

    @Test
    public void dumpAllRejectionLogs() {
        List<Class<? extends BPFProgram>> progs = List.of(
                RealVerifierClassificationTest.StackOobProg.class,
                RealVerifierClassificationTest.UncheckedNullDerefProg.class,
                RealVerifierClassificationTest.UnknownHelperProg.class,
                RealVerifierClassificationTest.OutOfBoundsProg.class,
                RealVerifierClassificationTest.InvalidMemAccessProg.class,
                RealVerifierClassificationTest.InfiniteLoopProg.class,
                RealVerifierClassificationTest.TypeMismatchProg.class
        );
        for (var cls : progs) {
            try (var ignored = BPFProgram.load(cls)) {
                System.out.println("=== " + cls.getSimpleName() + " ===");
                System.out.println("(loaded — no rejection)");
            } catch (BPFVerifierException ex) {
                System.out.println("=== " + cls.getSimpleName() + " ===");
                System.out.println(ex.verifierLog());
                System.out.println("--- classification ---");
                System.out.println(ex.errorClass().orElse(null));
            } catch (Throwable t) {
                System.out.println("=== " + cls.getSimpleName() + " (other failure) ===");
                System.out.println(t);
            }
        }
    }
}
