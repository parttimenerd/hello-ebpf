package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;

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

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;

    public BoundsCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        var packetOrigin = collectPacketOriginVars(body);
        if (packetOrigin.isEmpty()) return;

        var guarded = collectGuardedVars(body, packetOrigin);

        for (var name : packetOrigin) {
            if (guarded.contains(name)) continue;
            reportUnguardedDereferences(body, name);
        }
    }

    private Set<String> collectPacketOriginVars(BlockTree body) {
        var result = new HashSet<String>();
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void p) {
                var init = node.getInitializer();
                if (init != null && isPacketOriginExpression(init, result)) {
                    result.add(node.getName().toString());
                }
                return super.visitVariable(node, p);
            }

            @Override
            public Void visitAssignment(AssignmentTree node, Void p) {
                if (node.getVariable() instanceof IdentifierTree id
                        && isPacketOriginExpression(node.getExpression(), result)) {
                    result.add(id.getName().toString());
                }
                return super.visitAssignment(node, p);
            }
        }.scan(body, null);
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

    private void reportUnguardedDereferences(BlockTree body, String name) {
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                if (node.getMethodSelect() instanceof MemberSelectTree mst) {
                    var method = mst.getIdentifier().toString();
                    if (method.equals("val") && rootMatches(mst.getExpression(), name)) {
                        compilerPlugin.logWarning(methodPath, node,
                                "Packet pointer '" + name + "' dereferenced without any bounds check. "
                                        + "Guard with: if (" + name + ".add(N).greaterThan(end)) return XDP_ABORTED;");
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

    private static boolean rootMatches(ExpressionTree expr, String name) {
        var root = rootIdentifier(expr);
        return root != null && root.equals(name);
    }

    /**
     * Walk the receiver chain of {@code .add(...)}, {@code .sub(...)}, {@code .cast()},
     * {@code .val()} calls and parens to find the leaf identifier, if any.
     */
    private static String rootIdentifier(ExpressionTree expr) {
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
