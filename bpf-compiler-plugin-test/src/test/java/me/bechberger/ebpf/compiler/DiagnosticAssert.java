package me.bechberger.ebpf.compiler;

import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import java.util.List;
import java.util.Locale;

/**
 * Substring-based assertions over diagnostic lists. Avoids brittle exact-text
 * checks while still verifying the diagnostic contains all expected hints.
 */
public final class DiagnosticAssert {

    private DiagnosticAssert() {}

    /**
     * Assert that at least one ERROR diagnostic contains every {@code needle}
     * (case-insensitive substring match). Failure prints the full diagnostic
     * stream so the cause is obvious.
     */
    public static void assertContainsAll(List<Diagnostic<? extends JavaFileObject>> diagnostics,
                                         String... needles) {
        var lower = new String[needles.length];
        for (int i = 0; i < needles.length; i++) lower[i] = needles[i].toLowerCase(Locale.ROOT);

        outer:
        for (var d : diagnostics) {
            if (d.getKind() != Diagnostic.Kind.ERROR) continue;
            String msg = d.getMessage(Locale.ROOT).toLowerCase(Locale.ROOT);
            for (var n : lower) {
                if (!msg.contains(n)) continue outer;
            }
            return; // matched
        }

        var sb = new StringBuilder();
        sb.append("No ERROR diagnostic contains all of [");
        for (int i = 0; i < needles.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append('"').append(needles[i]).append('"');
        }
        sb.append("].\nDiagnostics observed:\n");
        for (var d : diagnostics) {
            sb.append("  ").append(d.getKind()).append(": ").append(d.getMessage(Locale.ROOT)).append('\n');
        }
        throw new AssertionError(sb.toString());
    }
}
