package me.bechberger.ebpf.bpf;

/**
 * BPF related error
 */
public class BPFError extends RuntimeException {

    public BPFError(String message) {
        super(message);
    }

    public BPFError(String message, Throwable cause) {
        super(message, cause);
    }

    public BPFError(String message, int errorCode) {
        this(message + ": " + Util.errnoString(errorCode) + " (" + errorCode + ")");
    }
}
