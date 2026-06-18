package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Pre-pass that rejects {@code bpf_probe_read*} calls whose size argument is the literal
 * {@code 0}. Stage 15.2 of the unified plan.
 *
 * <p>The verifier rejects probe-read calls with size 0 ({@code R2 !read_ok}); catch it at
 * javac-time so the user sees a 4-part message instead of a kernel-side rejection that
 * libbpf surfaces as {@code R2 !read_ok at insn N}.
 *
 * <p>Recognised helpers (signature: {@code helper(dst, size, src)}, size is arg index 1):
 * {@code bpf_probe_read}, {@code bpf_probe_read_user}, {@code bpf_probe_read_kernel},
 * {@code bpf_probe_read_str}, {@code bpf_probe_read_user_str}, {@code bpf_probe_read_kernel_str}.
 *
 * <p>Category: {@code bounds.probe-read-zero}.
 */
public final class ProbeReadSizeZeroPass {

    /** A single detected probe-read call with size 0. */
    public record Detection(Tree at, String category, String message) {}

    private static final Set<String> PROBE_READ_HELPERS = Set.of(
            "bpf_probe_read",
            "bpf_probe_read_user",
            "bpf_probe_read_kernel",
            "bpf_probe_read_str",
            "bpf_probe_read_user_str",
            "bpf_probe_read_kernel_str");

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public ProbeReadSizeZeroPass(CompilerPlugin compilerPlugin,
                                 TypedTreePath<MethodTree> methodPath,
                                 AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        for (var d : detect(body)) {
            if (ctx.isSuppressed(d.at(), d.category())) continue;
            compilerPlugin.logError(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection: walks {@code subtree} and returns every offending call. */
    public static List<Detection> detect(Tree subtree) {
        var out = new ArrayList<Detection>();
        new Visitor(out).scan(subtree, null);
        return out;
    }

    /** True if {@code e} is a literal {@code 0}, or {@code (0)}, or {@code +0} / {@code -0}. */
    static boolean isZeroLiteral(ExpressionTree e) {
        if (e instanceof ParenthesizedTree p) return isZeroLiteral(p.getExpression());
        if (e instanceof UnaryTree u
                && (u.getKind() == Tree.Kind.UNARY_MINUS || u.getKind() == Tree.Kind.UNARY_PLUS)) {
            return isZeroLiteral(u.getExpression());
        }
        if (e instanceof LiteralTree lit && lit.getValue() instanceof Number n) {
            return n.longValue() == 0L;
        }
        return false;
    }

    private static String helperName(MethodInvocationTree node) {
        var sel = node.getMethodSelect();
        if (sel instanceof IdentifierTree id) return id.getName().toString();
        if (sel instanceof MemberSelectTree mst) return mst.getIdentifier().toString();
        return "";
    }

    private static String message(String helper) {
        return helper + " called with size = 0.\n"
             + "Why: the BPF verifier rejects probe-read calls with a zero size (R2 !read_ok). "
             + "A zero-byte copy is always a bug — the destination buffer is left uninitialised.\n"
             + "Fix: pass the actual byte count to copy. For a fixed buffer 'byte[N] buf', use "
             + "'sizeof(buf)' (or the matching @Size constant). For a string, use the *_str variant "
             + "with the destination buffer's @Size value.\n"
             + "See: cookbook §Probe-read";
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final List<Detection> out;

        Visitor(List<Detection> out) { this.out = out; }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            var name = helperName(node);
            if (PROBE_READ_HELPERS.contains(name)) {
                var args = node.getArguments();
                // Signature: helper(dst, size, src) — size at index 1.
                if (args.size() >= 2 && isZeroLiteral(args.get(1))) {
                    out.add(new Detection(node, "bounds.probe-read-zero", message(name)));
                }
            }
            return super.visitMethodInvocation(node, unused);
        }
    }
}
