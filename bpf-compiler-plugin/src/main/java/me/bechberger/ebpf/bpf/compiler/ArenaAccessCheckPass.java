package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;

import java.util.HashSet;
import java.util.Set;

/**
 * Compile-time check for misuse of {@code @InArena} arena pointers.
 *
 * <p>Arena pointers live in clang AS1; the verifier and the BPF runtime treat
 * them differently from kernel pointers. Calling {@code Ptr.asLong()} on an
 * arena pointer converts it to a raw {@code u64}, which drops the
 * {@code __arena} address-space tag and produces code that loads as a raw
 * kernel address — almost always a bug. (The other "leak" shapes —
 * {@code (long) p}, {@code long x = p} — javac rejects outright since
 * {@code Ptr<T>} has no implicit conversion to {@code long}.)
 *
 * <p>The pass emits a {@code WARNING} (not error) at the Java source line
 * so a heuristic miss never breaks a build.
 *
 * <p>Tracked sources of arena pointers:
 * <ul>
 *   <li>Parameters / locals annotated {@code @InArena}.</li>
 *   <li>Local variables initialized from
 *       {@code BPFJ.bpfArenaAllocPages(...)}.</li>
 * </ul>
 */
public class ArenaAccessCheckPass {

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;

    public ArenaAccessCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        var arenaVars = new HashSet<String>();

        // Seed from @InArena-annotated parameters.
        for (var p : method.getParameters()) {
            if (hasInArena(p)) arenaVars.add(p.getName().toString());
        }

        // Seed from @InArena-annotated class fields of the enclosing class.
        var parentPath = methodPath.path().getParentPath();
        if (parentPath != null && parentPath.getLeaf() instanceof ClassTree cls) {
            for (var member : cls.getMembers()) {
                if (member instanceof VariableTree vt && hasInArena(vt)) {
                    arenaVars.add(vt.getName().toString());
                }
            }
        }

        // Walk the body to pick up @InArena locals and bpfArenaAllocPages results.
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                if (hasInArena(node)) {
                    arenaVars.add(node.getName().toString());
                } else if (node.getInitializer() != null
                        && isArenaAllocCall(node.getInitializer())) {
                    arenaVars.add(node.getName().toString());
                }
                return super.visitVariable(node, unused);
            }
        }.scan(body, null);

        if (arenaVars.isEmpty()) return;

        // Walk again to find leaks. The realistic Java-legal leak path is
        // `arenaPtr.asLong()` — javac rejects `(long) arenaPtr` and
        // `long x = arenaPtr` outright, so we don't need to guard those.
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                if (node.getMethodSelect() instanceof MemberSelectTree sel
                        && sel.getIdentifier().toString().equals("asLong")) {
                    var receiver = sel.getExpression();
                    var src = arenaSourceName(receiver, arenaVars);
                    if (src != null) {
                        report(node, src);
                    }
                }
                return super.visitMethodInvocation(node, unused);
            }
        }.scan(body, null);
    }

    private static boolean hasInArena(VariableTree v) {
        for (var a : v.getModifiers().getAnnotations()) {
            var name = a.getAnnotationType().toString();
            if (name.equals("InArena") || name.endsWith(".InArena")) return true;
        }
        return false;
    }

    /** True if {@code expr} is a {@code BPFJ.bpfArenaAllocPages(...)} call. */
    private boolean isArenaAllocCall(ExpressionTree expr) {
        var stripped = unwrap(expr);
        if (!(stripped instanceof MethodInvocationTree call)) return false;
        var sym = methodSymbol(call);
        if (sym == null) return false;
        var name = sym.getSimpleName().toString();
        var owner = sym.owner != null ? sym.owner.getQualifiedName().toString() : "";
        return name.equals("bpfArenaAllocPages") && owner.equals("me.bechberger.ebpf.bpf.BPFJ");
    }

    /**
     * If {@code expr} (after unwrapping parens) is, or trivially derives from,
     * a tracked arena variable, return that variable's name. Otherwise null.
     *
     * <p>"Trivially derives" covers: identifier reference, parenthesised,
     * {@code this.field} member-select, and pass-throughs that don't change
     * address-space semantics. Anything richer (method call, computed index)
     * is not tracked — keeps this MVP false-positive free.
     */
    private static String arenaSourceName(ExpressionTree expr, Set<String> tracked) {
        var e = unwrap(expr);
        if (e instanceof IdentifierTree id) {
            var name = id.getName().toString();
            return tracked.contains(name) ? name : null;
        }
        // this.fieldName — explicit this-qualified field reference
        if (e instanceof MemberSelectTree ms) {
            var receiver = unwrap(ms.getExpression());
            if (receiver instanceof IdentifierTree rid && rid.getName().contentEquals("this")) {
                var name = ms.getIdentifier().toString();
                return tracked.contains(name) ? name : null;
            }
        }
        return null;
    }

    private void report(Tree node, String varName) {
        compilerPlugin.logWarning(methodPath, node,
                "Arena pointer '" + varName + "'.asLong() drops the __arena "
                        + "address-space tag. Keep the value as a Ptr<T>, or "
                        + "bridge to user space with BPFJ.castUser(" + varName + ").");
    }

    private static ExpressionTree unwrap(ExpressionTree expr) {
        while (expr instanceof ParenthesizedTree paren) expr = paren.getExpression();
        return expr;
    }

    private static MethodSymbol methodSymbol(MethodInvocationTree call) {
        try {
            return switch (call.getMethodSelect()) {
                case com.sun.tools.javac.tree.JCTree.JCFieldAccess fa -> (MethodSymbol) fa.sym;
                case com.sun.tools.javac.tree.JCTree.JCIdent id -> (MethodSymbol) id.sym;
                default -> null;
            };
        } catch (ClassCastException e) {
            return null;
        }
    }
}
