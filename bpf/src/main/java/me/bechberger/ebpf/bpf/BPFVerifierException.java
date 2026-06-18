package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.compiler.verifier.VerifierFixSuggester;
import me.bechberger.ebpf.bpf.compiler.verifier.VerifierLogParser;

/**
 * Thrown when {@code bpf_object__load} fails and we have captured verifier output via
 * {@link VerifierLogCapture}. The exception message embeds a humane summary (classification
 * plus a 4-part Why/Fix/See hint), the original errno string, and the full verifier log.
 *
 * <p>Note: the BPF compiler plugin emits {@code #line N "Foo.java"} directives into the
 * generated C, so clang propagates Java source coordinates into BTF/DWARF and the
 * verifier prints them directly in its log. A separate {@code .linemap} sidecar to map
 * C lines back to Java source is therefore unnecessary.</p>
 */
public class BPFVerifierException extends BPFProgram.BPFLoadError {

    private final String verifierLog;
    private final transient VerifierLogParser.ParseResult parsed;

    public BPFVerifierException(String shortMsg, String verifierLog) {
        super(buildMessage(shortMsg, verifierLog));
        this.verifierLog = verifierLog == null ? "" : verifierLog;
        this.parsed = VerifierLogParser.parse(this.verifierLog);
    }

    private static String buildMessage(String shortMsg, String verifierLog) {
        var safeShort = shortMsg == null ? "" : shortMsg;
        var safeLog = verifierLog == null ? "" : verifierLog;
        var parsed = VerifierLogParser.parse(safeLog);
        var sb = new StringBuilder(safeShort);
        if (parsed.error().isPresent()) {
            sb.append("\n\n--- summary ---\n");
            sb.append(VerifierFixSuggester.formatHumane(parsed));
        }
        sb.append("\n--- verifier log ---\n").append(safeLog);
        return sb.toString();
    }

    /** Raw verifier log text captured from libbpf during {@code bpf_object__load}. */
    public String verifierLog() {
        return verifierLog;
    }

    /** Structured form of the verifier log. Empty when nothing parseable was captured. */
    public VerifierLogParser.ParseResult parsed() {
        return parsed;
    }

    /** Coarse classification of the verifier rejection, or empty when no error line was found. */
    public java.util.Optional<VerifierLogParser.ErrorClass> errorClass() {
        return parsed.error().map(VerifierLogParser.VerifierError::errorClass);
    }
}
