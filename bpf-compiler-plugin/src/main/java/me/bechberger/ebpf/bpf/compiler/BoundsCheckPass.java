package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.HashSet;
import java.util.Set;

/**
 * Conservative MVP packet-data bounds-check pass.
 *
 * <p>Flags dereferences of pointers that originate from {@code xdp_md.data} /
 * {@code __sk_buff.data} when the enclosing method contains no bounds-check
 * guard mentioning that pointer.
 *
 * <p>Recognised packet-origin sources for a local variable {@code p}:
 * <ul>
 *   <li>{@code p = Ptr.voidPointer(<X>.data)}</li>
 *   <li>{@code p = <X>.data}</li>
 *   <li>{@code p = otherPacketOrigin.cast()} / {@code .add(...)} (transitive)</li>
 * </ul>
 *
 * <p>A "bounds-check guard" is any {@code .greaterThan(...)} / {@code .lessThan(...)}
 * call appearing anywhere in the method body whose receiver mentions one of the
 * tracked pointer names. Pointer arithmetic ({@code p.add(...).greaterThan(end)})
 * counts as guarding {@code p}.
 *
 * <p>If no guard at all is present, every {@code p.val()} dereference of {@code p}
 * is reported as a {@code WARNING}. The MVP intentionally avoids hard errors so a
 * heuristic miss never breaks a real build; the threshold can be promoted to error
 * in a follow-up after running on all samples.
 */
public class BoundsCheckPass {

    /** A single detected unguarded packet-pointer dereference. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    /**
     * Pure detection: run the bounds-check pass on {@code method} and return every unguarded
     * dereference without needing a live {@link CompilerPlugin}. For unit testing.
     */
    public static java.util.List<Detection> detect(MethodTree method) {
        var detections = new java.util.ArrayList<Detection>();
        var pass = new BoundsCheckPass(null, null, new AnalysisContext()) {
            @Override
            void emitUnguardedDeref(Tree at, String name) {
                String msg = "Packet pointer '" + name + "' dereferenced without any bounds check.\n"
                           + "Why: the verifier requires every packet-pointer deref to be preceded by "
                           + "a comparison against the packet's end pointer.\n"
                           + "Fix: add a bounds check before the deref.\n"
                           + "See: cookbook §Packet bounds";
                detections.add(new Detection(at, "bounds.unguarded-packet-deref", msg));
            }
        };
        var body = method.getBody();
        if (body != null) {
            var packetOrigin = pass.collectPacketOriginVars(body);
            if (!packetOrigin.isEmpty()) {
                var guarded = pass.collectGuardedVars(body, packetOrigin);
                for (var pname : packetOrigin) {
                    if (!guarded.contains(pname)) pass.reportUnguardedDereferences(body, pname);
                }
            }
        }
        return detections;
    }

    public BoundsCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this(compilerPlugin, methodPath, new AnalysisContext());
    }

    public BoundsCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                           AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        var packetOrigin = collectPacketOriginVars(body);
        if (packetOrigin.isEmpty()) return;

        var guarded = collectGuardedVars(body, packetOrigin);

        // Record guarded packet derefs in the shared context so the Translator / future passes
        // can decide whether direct -> access is safe.
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                if (node.getMethodSelect() instanceof MemberSelectTree mst
                        && mst.getIdentifier().contentEquals("val")) {
                    var root = rootIdentifier(mst.getExpression());
                    if (root != null && guarded.contains(root)) ctx.packetGuarded.add(node);
                }
                return super.visitMethodInvocation(node, p);
            }
        }.scan(body, null);

        for (var name : packetOrigin) {
            if (guarded.contains(name)) continue;
            reportUnguardedDereferences(body, name);
        }
    }

    private Set<String> collectPacketOriginVars(BlockTree body) {
        var result = new HashSet<String>();
        // Iterate to a fixpoint: each pass may discover transitive origins (e.g. `p = q.cast()`
        // before `q = ctx.data`). Stop when no new names are added.
        int prevSize;
        do {
            prevSize = result.size();
            new TreeScanner<Void, Void>() {
                @Override
                public Void visitVariable(VariableTree node, Void p) {
                    var init = node.getInitializer();
                    if (init != null && !result.contains(node.getName().toString())
                            && isPacketOriginExpression(init, result)) {
                        result.add(node.getName().toString());
                    }
                    return super.visitVariable(node, p);
                }

                @Override
                public Void visitAssignment(AssignmentTree node, Void p) {
                    if (node.getVariable() instanceof IdentifierTree id) {
                        var name = id.getName().toString();
                        if (!result.contains(name)
                                && isPacketOriginExpression(node.getExpression(), result)) {
                            result.add(name);
                        }
                    }
                    return super.visitAssignment(node, p);
                }
            }.scan(body, null);
        } while (result.size() > prevSize);
        return result;
    }

    /**
     * True if {@code expr} is rooted in a packet origin: {@code X.data},
     * {@code Ptr.voidPointer(X.data)}, or a transitive {@code .cast()} / {@code .add(...)}
     * on an already-known packet-origin variable.
     */
    private boolean isPacketOriginExpression(ExpressionTree expr, Set<String> known) {
        ExpressionTree e = unwrap(expr);
        if (e instanceof MemberSelectTree mst) {
            return mst.getIdentifier().contentEquals("data");
        }
        if (e instanceof MethodInvocationTree call) {
            var sel = call.getMethodSelect();
            if (sel instanceof MemberSelectTree mst) {
                var name = mst.getIdentifier().toString();
                if (name.equals("voidPointer") && call.getArguments().size() == 1) {
                    return isPacketOriginExpression(call.getArguments().get(0), known);
                }
                if (name.equals("cast") || name.equals("add") || name.equals("sub")) {
                    return isPacketOriginExpression(mst.getExpression(), known);
                }
            }
        }
        if (e instanceof IdentifierTree id) {
            return known.contains(id.getName().toString());
        }
        return false;
    }

    private Set<String> collectGuardedVars(BlockTree body, Set<String> tracked) {
        var result = new HashSet<String>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                if (node.getMethodSelect() instanceof MemberSelectTree mst) {
                    var name = mst.getIdentifier().toString();
                    if (name.equals("greaterThan") || name.equals("lessThan")
                            || name.equals("greaterThanOrEqualTo") || name.equals("lessThanOrEqualTo")) {
                        addRoot(mst.getExpression());
                        for (var arg : node.getArguments()) addRoot(arg);
                    }
                }
                return super.visitMethodInvocation(node, p);
            }

            private void addRoot(ExpressionTree expr) {
                var name = rootIdentifier(expr);
                if (name != null && tracked.contains(name)) {
                    result.add(name);
                }
            }
        }.scan(body, null);
        return result;
    }

    /**
     * Overridable hook for unguarded packet-pointer dereference warnings.
     * Default calls {@link CompilerPlugin#logWarning}; the pure-detection subclass in
     * {@link #detect(MethodTree)} overrides to collect {@link Detection} records.
     */
    void emitUnguardedDeref(Tree at, String name) {
        if (compilerPlugin == null) return;
        compilerPlugin.logWarning(methodPath, at,
                "Packet pointer '" + name + "' dereferenced without any bounds check.\n"
              + "Why: the verifier requires every packet-pointer deref to be preceded by "
              + "a comparison against the packet's end pointer; otherwise the program "
              + "will not load.\n"
              + "Fix: add a bounds check before the deref:\n"
              + "  if (" + name + ".add(N).greaterThan(end)) return XDP_ABORTED;\n"
              + "  /* now safe to read " + name + ".val() */\n"
              + "See: cookbook §Packet bounds");
    }

    private void reportUnguardedDereferences(BlockTree body, String name) {
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                if (node.getMethodSelect() instanceof MemberSelectTree mst) {
                    var method = mst.getIdentifier().toString();
                    if (method.equals("val") && rootMatches(mst.getExpression(), name)) {
                        emitUnguardedDeref(node, name);
                    }
                }
                return super.visitMethodInvocation(node, p);
            }

            @Override
            public Void visitMemberSelect(MemberSelectTree node, Void p) {
                // Direct field access on the packet pointer: p.field — also a deref.
                // (val() handled above; this catches generated code without explicit val().)
                if (rootMatches(node.getExpression(), name)
                        && !node.getIdentifier().contentEquals("data")
                        && !node.getIdentifier().contentEquals("data_end")) {
                    // Skip: field access is only a deref if the receiver is itself a deref;
                    // bare `p.field` on Ptr<T> is rare in this codebase. Conservative: do not flag.
                }
                return super.visitMemberSelect(node, p);
            }
        }.scan(body, null);
    }

    static boolean rootMatches(ExpressionTree expr, String name) {
        var root = rootIdentifier(expr);
        return root != null && root.equals(name);
    }

    /**
     * Walk the receiver chain of {@code .add(...)}, {@code .sub(...)}, {@code .cast()},
     * {@code .val()} calls and parens to find the leaf identifier, if any.
     */
    static String rootIdentifier(ExpressionTree expr) {
        ExpressionTree e = unwrap(expr);
        while (true) {
            if (e instanceof IdentifierTree id) return id.getName().toString();
            if (e instanceof MethodInvocationTree call
                    && call.getMethodSelect() instanceof MemberSelectTree mst) {
                var name = mst.getIdentifier().toString();
                if (name.equals("add") || name.equals("sub") || name.equals("cast") || name.equals("val")) {
                    e = unwrap(mst.getExpression());
                    continue;
                }
            }
            return null;
        }
    }

    private static ExpressionTree unwrap(ExpressionTree expr) {
        while (expr instanceof ParenthesizedTree paren) expr = paren.getExpression();
        return expr;
    }
}
