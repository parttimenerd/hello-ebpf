package me.bechberger.ebpf.bpf;

/**
 * BPF related error
 */
public class BPFError extends RuntimeException {

    /** -1 when no errno was captured (string-only constructors) */
    private final int errorCode;

    public BPFError(String message) {
        super(message);
        this.errorCode = -1;
    }

    public BPFError(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = -1;
    }

    public BPFError(String message, int errorCode) {
        super(message + ": " + Util.errnoString(errorCode) + " (" + errorCode + ")");
        this.errorCode = errorCode;
    }

    /** Returns the errno value, or {@code -1} if this error was not constructed with one. */
    public int getErrorCode() {
        return errorCode;
    }
}
