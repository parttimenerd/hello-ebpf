package me.bechberger.ebpf.bcc;

/**
 * Exception thrown when a BPF call fails (but not always)
 */
public class BPFCallException extends RuntimeException {
    private final int errno;

    public BPFCallException(String message, int errno) {
        super(message + ": " + PanamaUtil.errnoString(errno));
        this.errno = errno;
    }

    public BPFCallException(String message) {
        super(message);
        this.errno = 0;
    }
}
