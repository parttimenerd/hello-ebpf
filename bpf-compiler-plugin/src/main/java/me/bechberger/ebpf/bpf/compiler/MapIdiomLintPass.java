package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-pass that lints common BPF map / ring-buffer misuse patterns. Stage 12 of the unified plan.
 *
 * <p>These patterns reliably cause verifier rejection or runtime resource leaks; reporting them
 * with a 4-part message at javac time is cheaper than chasing them through verifier logs.
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code map.unchecked-lookup} — {@code map.bpf_get(k).val()} or
 *       {@code map.bpf_get(k).<member>} with no intervening null check. The verifier rejects this
 *       because {@code bpf_map_lookup_elem} can return NULL.</li>
 *   <li>{@code ringbuf.no-submit} — a method that calls {@code reserve()} on a ring buffer but
 *       has no matching {@code submit(...)} or {@code discard(...)} anywhere in the body. The
 *       reserved slot leaks.</li>
 * </ul>
 *
 * <p>Detection is purely AST-shape; it does not consult the dataflow lattices. A more precise
 * version (using {@code NullabilityAnalyzer}'s output) is possible but would couple this pass
 * to pass-ordering. The current shape catches the obvious cases without that coupling.
 */
public final class MapIdiomLintPass {

    /** A single detected misuse. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public MapIdiomLintPass(CompilerPlugin compilerPlugin,
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
            compilerPlugin.logWarning(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection. Walks the given subtree and returns every detected misuse. */
    public static List<Detection> detect(Tree subtree) {
        var out = new ArrayList<Detection>();
        new Visitor(out).scan(subtree, null);
        // Whole-method check: reserve() called but no submit/discard anywhere.
        var counts = new ReserveCommitCounter();
        counts.scan(subtree, null);
        if (counts.reserveCalls > 0 && counts.commitOrDiscardCalls == 0) {
            out.add(new Detection(subtree, "ringbuf.no-submit",
                    "Ring-buffer reserve() with no matching submit() or discard().\n"
                  + "Why: a reserved slot must be released via submit (publish) or discard (drop). "
                  + "Leaving it reserved leaks the slot until the BPF program reloads.\n"
                  + "Fix: call '.submit(event)' on the success path and '.discard(event)' on every "
                  + "early-return path. A try-finally pattern is not available in BPF; mirror the "
                  + "shape used in samples/RingBufferDemo.java.\n"
                  + "See: cookbook §Ring buffers"));
        }
        return out;
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final List<Detection> out;

        Visitor(List<Detection> out) { this.out = out; }

        @Override
        public Void visitMemberSelect(MemberSelectTree node, Void unused) {
            // Pattern: <bpf_get-call>.<member>  (where member is .val() or a struct field)
            ExpressionTree receiver = unwrapParens(node.getExpression());
            if (receiver instanceof MethodInvocationTree mi && isBpfGet(mi)) {
                out.add(new Detection(node, "map.unchecked-lookup",
                        formatUncheckedLookupMessage()));
            }
            return super.visitMemberSelect(node, unused);
        }

        private static ExpressionTree unwrapParens(ExpressionTree e) {
            while (e instanceof ParenthesizedTree p) e = p.getExpression();
            return e;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            // Pattern: <bpf_get-call>.val()  — the visitMemberSelect above already catches this
            // because val() is a MemberSelectTree under the invocation. So no extra work here.
            return super.visitMethodInvocation(node, unused);
        }

        private static boolean isBpfGet(MethodInvocationTree mi) {
            if (mi.getMethodSelect() instanceof MemberSelectTree ms) {
                String name = ms.getIdentifier().toString();
                // Be strict: only match the canonical BPFBaseMap.bpf_get name. Matching plain
                // "get" would false-positive on Map.get / List.get / Optional.get / etc.
                return name.equals("bpf_get");
            }
            return false;
        }

        private static String formatUncheckedLookupMessage() {
            return "Map lookup result dereferenced without a null check.\n"
                 + "Why: bpf_map_lookup_elem can return NULL; the verifier rejects any deref of "
                 + "the result without first proving it is non-null.\n"
                 + "Fix: store the lookup in a local, null-check it, then deref:\n"
                 + "  Ptr<V> p = map.bpf_get(k);\n"
                 + "  if (p == null) return 0;\n"
                 + "  /* now safe: p.val() / p.field */\n"
                 + "See: cookbook §Map lookups";
        }
    }

    /** Counts reserve() vs submit()/discard() calls on what looks like a BPFRingBuffer. */
    private static final class ReserveCommitCounter extends TreeScanner<Void, Void> {
        int reserveCalls;
        int commitOrDiscardCalls;

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            if (node.getMethodSelect() instanceof MemberSelectTree ms
                    && node.getArguments().size() <= 1) {
                String name = ms.getIdentifier().toString();
                // We can't disambiguate "reserve" from a non-ringbuf "reserve" without symbols,
                // but the misuse pattern (reserve with no submit/discard in the same method) is
                // specific enough that the false-positive rate is low. A user can suppress with
                // @SuppressBPFWarning("ringbuf.no-submit").
                if (name.equals("reserve") && node.getArguments().isEmpty()) reserveCalls++;
                else if (name.equals("submit") || name.equals("discard")) commitOrDiscardCalls++;
            }
            return super.visitMethodInvocation(node, unused);
        }
    }
}
