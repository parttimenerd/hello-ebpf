package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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

    /** A single detected arena-pointer misuse. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    /**
     * Pure detection: run the arena-access check on {@code method} and return every
     * arena-pointer leak without needing a live {@link CompilerPlugin}. For unit testing.
     */
    public static java.util.List<Detection> detect(MethodTree method) {
        var detections = new java.util.ArrayList<Detection>();
        var pass = new ArenaAccessCheckPass(null, null, new AnalysisContext()) {
            @Override
            void emitArenaLeak(Tree at, String varName, String originDesc) {
                String msg = "Arena pointer '" + varName + "'.asLong() drops the __arena address-space tag.\n"
                           + "Why: " + originDesc + "; arena addresses carry a verifier tag that is lost on cast to long.\n"
                           + "Fix: keep the value as Ptr<T>, or bridge via BPFJ.castUser(" + varName + ").\n"
                           + "See: cookbook §Arena";
                detections.add(new Detection(at, "arena.aslong-leak", msg));
            }
        };
        pass.analyzeMethod(method);
        return detections;
    }

    /** Visible for the detect() path. */
    private void analyzeMethod(MethodTree method) {
        var body = method.getBody();
        if (body == null) return;
        analyzeBody(body, method.getParameters());
    }

    /** Factor out the core scan logic so detect() can call it without a TypedTreePath. */
    private void analyzeBody(BlockTree body,
            java.util.List<? extends VariableTree> params) {
        var arenaVars = new HashSet<String>();
        var arenaSourceSite = new HashMap<String, Tree>();

        for (var p : params) {
            if (hasInArena(p)) {
                arenaVars.add(p.getName().toString());
                arenaSourceSite.put(p.getName().toString(), p);
            }
        }

        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                var name = node.getName().toString();
                if (hasInArena(node)) {
                    arenaVars.add(name);
                    arenaSourceSite.put(name, node);
                } else if (node.getInitializer() != null
                        && isArenaAllocCall(node.getInitializer())) {
                    arenaVars.add(name);
                    arenaSourceSite.put(name, node);
                } else if (arenaVars.contains(name)) {
                    arenaVars.remove(name);
                    arenaSourceSite.remove(name);
                }
                return super.visitVariable(node, unused);
            }
        }.scan(body, null);

        if (arenaVars.isEmpty()) return;

        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                if (node.getMethodSelect() instanceof MemberSelectTree sel
                        && sel.getIdentifier().toString().equals("asLong")) {
                    var receiver = sel.getExpression();
                    var src = arenaSourceName(receiver, arenaVars);
                    if (src != null) {
                        report(node, src, arenaSourceSite.get(src));
                    }
                }
                return super.visitMethodInvocation(node, unused);
            }
        }.scan(body, null);
    }

    /**
     * Overridable hook for arena-pointer leak warnings.
     * Default calls {@link CompilerPlugin#logWarning}; the pure-detection subclass in
     * {@link #detect(MethodTree)} overrides to collect {@link Detection} records.
     */
    void emitArenaLeak(Tree at, String varName, String originDesc) {
        if (compilerPlugin == null) return;
        compilerPlugin.logWarning(methodPath, at,
                "Arena pointer '" + varName + "'.asLong() drops the __arena address-space tag.\n"
              + "Why: " + originDesc + "; arena addresses are tracked by the verifier with a special "
              + "tag, and converting to a long erases that tag — any later use is treated as a raw "
              + "integer, preventing arena-aware checks from succeeding.\n"
              + "Fix: keep the value as a Ptr<T> through the call chain, or bridge to user space "
              + "explicitly via BPFJ.castUser(" + varName + ").\n"
              + "See: cookbook §Arena");
    }

    public ArenaAccessCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this(compilerPlugin, methodPath, new AnalysisContext());
    }

    public ArenaAccessCheckPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                                AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        var arenaVars = new HashSet<String>();
        var arenaSourceSite = new HashMap<String, Tree>();

        // Seed from @InArena-annotated parameters.
        for (var p : method.getParameters()) {
            if (hasInArena(p)) {
                arenaVars.add(p.getName().toString());
                arenaSourceSite.put(p.getName().toString(), p);
            }
        }

        // Seed from @InArena-annotated class fields of the enclosing class.
        var parentPath = methodPath.path().getParentPath();
        if (parentPath != null && parentPath.getLeaf() instanceof ClassTree cls) {
            for (var member : cls.getMembers()) {
                if (member instanceof VariableTree vt && hasInArena(vt)) {
                    arenaVars.add(vt.getName().toString());
                    arenaSourceSite.put(vt.getName().toString(), vt);
                }
            }
        }

        // Walk the body to pick up @InArena locals and bpfArenaAllocPages results.
        // A plain local with the same name as a tracked class field shadows the field within
        // this method body — drop it from arenaVars so we don't false-flag a non-arena local.
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                var name = node.getName().toString();
                if (hasInArena(node)) {
                    arenaVars.add(name);
                    arenaSourceSite.put(name, node);
                } else if (node.getInitializer() != null
                        && isArenaAllocCall(node.getInitializer())) {
                    arenaVars.add(name);
                    arenaSourceSite.put(name, node);
                } else if (arenaVars.contains(name)) {
                    arenaVars.remove(name);
                    arenaSourceSite.remove(name);
                }
                return super.visitVariable(node, unused);
            }
        }.scan(body, null);

        if (arenaVars.isEmpty()) return;

        // Walk again to find leaks.
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
                if (node.getMethodSelect() instanceof MemberSelectTree sel
                        && sel.getIdentifier().toString().equals("asLong")) {
                    var receiver = sel.getExpression();
                    var src = arenaSourceName(receiver, arenaVars);
                    if (src != null) {
                        report(node, src, arenaSourceSite.get(src));
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

    private void report(Tree node, String varName, Tree definingSite) {
        var origin = describeOrigin(definingSite, varName);
        emitArenaLeak(node, varName, origin);
    }

    /** Render "allocated at line N via bpfArenaAllocPages" or similar. */
    private String describeOrigin(Tree site, String varName) {
        if (site == null) return "'" + varName + "' is an arena pointer";
        long line = lineOf(site);
        var locPart = line > 0 ? " at line " + line : "";
        if (site instanceof VariableTree v) {
            if (v.getInitializer() != null && isArenaAllocCall(v.getInitializer())) {
                return "'" + varName + "' was allocated" + locPart + " via BPFJ.bpfArenaAllocPages(...)";
            }
            if (hasInArena(v)) {
                return "'" + varName + "' is declared @InArena" + locPart;
            }
        }
        return "'" + varName + "' is an arena pointer (declared" + locPart + ")";
    }

    private long lineOf(Tree tree) {
        if (tree == null || compilerPlugin == null || compilerPlugin.trees == null) return 0;
        var cu = methodPath.root();
        var sp = compilerPlugin.trees.getSourcePositions();
        long pos = sp.getStartPosition(cu, tree);
        if (pos == javax.tools.Diagnostic.NOPOS) return 0;
        return cu.getLineMap().getLineNumber(pos);
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
