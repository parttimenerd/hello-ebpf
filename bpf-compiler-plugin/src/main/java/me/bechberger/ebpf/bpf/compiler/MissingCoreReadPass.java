package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-pass that flags direct field access on a {@code Ptr.cast()}-rooted receiver. Stage 15.3.
 *
 * <p>The verifier rejects naked {@code ->} on a kernel pointer that the static auto-emit can
 * neither lift to {@code BPF_CORE_READ} nor wrap with {@code bpf_probe_read_kernel}. The most
 * common leftover shape is the user reaching for an untyped pointer (e.g. {@code Ptr<Object>}
 * or a void-pointer-equivalent), {@code .cast()}-ing it, and then accessing a field directly:
 *
 * <pre>{@code
 *   Ptr<Foo> p = somePtr.<Foo>cast();
 *   int x = p.val().field;   // ← direct access on cast-result; CO-RE is bypassed
 * }</pre>
 *
 * <p>This pass is purely syntactic: it fires when a {@code MemberSelectTree}'s receiver chain
 * roots in a {@code .cast()} call (with optional {@code .val()} hops). The fix-it tells the
 * user to use {@code BPF_CORE_READ}-style chained access (typically by giving the cast target
 * type a CO-RE-tagged {@code @Type @Builtin} declaration), or to copy the bytes via
 * {@code bpf_probe_read_kernel}.
 *
 * <p>Category: {@code region.missing-core-read}.
 */
public final class MissingCoreReadPass {

    /** A single detected direct-access-on-cast shape. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public MissingCoreReadPass(CompilerPlugin compilerPlugin,
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

    /** Pure detection: walks {@code subtree} and returns every offending field access. */
    public static List<Detection> detect(Tree subtree) {
        var out = new ArrayList<Detection>();
        new Visitor(out).scan(subtree, null);
        return out;
    }

    /**
     * True when {@code e} reduces to a {@code .cast()} method invocation, possibly through
     * intermediate {@code .val()} calls and parentheses.
     *
     * <p>We deliberately stop after the first non-cast/non-val/non-paren node — chained
     * {@code .field.cast()} (cast on a sub-expression result) doesn't count, since the field
     * access happens *before* the cast and isn't the suspect site.
     */
    static boolean rootsInPtrCast(ExpressionTree e) {
        e = unwrap(e);
        if (e instanceof MethodInvocationTree mit) {
            var name = invokedName(mit);
            if ("cast".equals(name) || "castValPtr".equals(name)) return true;
            if ("val".equals(name)) {
                // Step into the receiver of `.val()` — the cast may sit one hop below.
                var sel = mit.getMethodSelect();
                if (sel instanceof MemberSelectTree mst) return rootsInPtrCast(mst.getExpression());
            }
        }
        return false;
    }

    private static ExpressionTree unwrap(ExpressionTree e) {
        while (e instanceof ParenthesizedTree p) e = p.getExpression();
        return e;
    }

    /** Returns the simple method name of an invocation, or empty string when not extractable. */
    private static String invokedName(MethodInvocationTree node) {
        var sel = node.getMethodSelect();
        if (sel instanceof IdentifierTree id) return id.getName().toString();
        if (sel instanceof MemberSelectTree mst) return mst.getIdentifier().toString();
        return "";
    }

    private static String message(String fieldName) {
        return "Direct field access on a Ptr.cast() result will be rejected by the verifier "
             + "('" + fieldName + "' read on a cast-through pointer).\n"
             + "Why: BPF cannot follow a kernel-typed pointer obtained from a void* cast — "
             + "without CO-RE relocations or a probe-read copy, the verifier sees an untracked "
             + "pointer and refuses to load. The plugin's CO-RE auto-lift only fires when the "
             + "pointer's static type is a CO-RE-tagged kernel BTF struct; a Ptr.<T>cast() "
             + "result is opaque to that check.\n"
             + "Fix: either declare the cast target type as a kernel BTF struct (so the auto-lift "
             + "uses 'BPF_CORE_READ(p, " + fieldName + ")'), or copy the bytes explicitly with "
             + "'BPFHelpers.bpf_probe_read_kernel(Ptr.of(local), sizeof(local), p)' and read the "
             + "field from 'local'.\n"
             + "See: cookbook §CO-RE";
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final List<Detection> out;

        Visitor(List<Detection> out) { this.out = out; }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            // Skip the method-name selector itself (e.g. the `cast().val` MemberSelect in
            // `p.cast().val()` is the call target, not a field access). Visit the receiver
            // expression of the call's selector and the arguments, but not the selector's
            // own MemberSelect node.
            var sel = node.getMethodSelect();
            if (sel instanceof MemberSelectTree mst) {
                scan(mst.getExpression(), null);
            } else {
                scan(sel, null);
            }
            for (var arg : node.getArguments()) scan(arg, null);
            for (var ta : node.getTypeArguments()) scan(ta, null);
            return null;
        }

        @Override
        public Void visitMemberSelect(MemberSelectTree node, Void unused) {
            var recv = unwrap(node.getExpression());
            if (recv instanceof MethodInvocationTree && rootsInPtrCast(node.getExpression())) {
                out.add(new Detection(node, "region.missing-core-read",
                        message(node.getIdentifier().toString())));
            }
            return super.visitMemberSelect(node, unused);
        }
    }
}
