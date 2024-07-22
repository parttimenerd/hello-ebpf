package me.bechberger.ebpf.annotations.bpf;

/**
 * Exception to indicate that a method should not be executed by
 * the JVM but is a BPF related function
 */
public class MethodIsBPFRelatedFunction extends RuntimeException {

    public MethodIsBPFRelatedFunction() {
        super("This method is a BPF related function and should not be executed by the JVM");
    }
}
