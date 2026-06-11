package me.bechberger.ebpf.bpf;

/**
 * Thrown when {@code bpf_object__load} fails and we have captured verifier output via
 * {@link VerifierLogCapture}. The exception message embeds the original short error
 * (typically an errno string) plus the full verifier log, so the user sees the kernel
 * diagnostic without having to re-run with extra logging.
 *
 * <p>Note: the BPF compiler plugin emits {@code #line N "Foo.java"} directives into the
 * generated C, so clang propagates Java source coordinates into BTF/DWARF and the
 * verifier prints them directly in its log. A separate {@code .linemap} sidecar to map
 * C lines back to Java source is therefore unnecessary.</p>
 */
public class BPFVerifierException extends BPFProgram.BPFLoadError {

    private final String verifierLog;

    public BPFVerifierException(String shortMsg, String verifierLog) {
        super(shortMsg + "\n--- verifier log ---\n" + verifierLog);
        this.verifierLog = verifierLog == null ? "" : verifierLog;
    }

    /** Raw verifier log text captured from libbpf during {@code bpf_object__load}. */
    public String verifierLog() {
        return verifierLog;
    }
}
