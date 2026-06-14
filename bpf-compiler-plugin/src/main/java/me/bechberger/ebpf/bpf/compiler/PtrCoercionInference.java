package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;

import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;

/**
 * Stage 6 — D10 auto-{@code Ptr} at call sites. Marks call-site arguments and assignment RHS
 * with one of {@link Coercion#TAKE_ADDRESS} / {@link Coercion#DEREFERENCE} / {@link Coercion#NONE}
 * so the {@code Translator} can emit {@code &} / {@code *} / nothing accordingly.
 *
 * <p>Per plan §"Stage 6 specification" the coercion is gated on region compatibility — see
 * {@link #regionAllowsCoercion(MemoryRegion, MemoryRegion)}. A region mismatch suppresses the
 * coercion (the existing {@code RegionAnalyzer} reports the {@code region.mixing} error
 * separately).
 *
 * <p>Opt-out: a parameter annotated {@code @PassByRef} keeps its argument verbatim — used for
 * atomics where identity matters.
 *
 * <h2>Pure-syntactic helpers</h2>
 * The {@link #classifyCoercion(boolean, boolean)} helper is unit-testable in isolation; the
 * AST-walking part requires javac attribution and is exercised through the integration tests.
 */
public final class PtrCoercionInference {

    /** Coercion to apply at an expression site. */
    public enum Coercion {
        NONE,
        /** {@code X} → {@code Ptr<X>}: emit {@code &expr}. */
        TAKE_ADDRESS,
        /** {@code Ptr<X>} → {@code X}: emit {@code *expr}. */
        DEREFERENCE
    }

    /** Slot for the per-tree coercion map. {@code Translator} reads via {@link AnalysisContext#get}. */
    public static final AnalysisContext.Slot<Coercion> COERCE =
            AnalysisContext.slot("ptr-coerce");

    /** Fully-qualified name of the {@code Ptr<T>} type. */
    public static final String PTR_TYPE = "me.bechberger.ebpf.type.Ptr";

    /** Fully-qualified name of the {@code @PassByRef} annotation. */
    public static final String PASS_BY_REF_ANNOTATION = "me.bechberger.ebpf.annotations.PassByRef";

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public PtrCoercionInference(CompilerPlugin compilerPlugin,
                                TypedTreePath<MethodTree> methodPath,
                                AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        var trees = compilerPlugin.trees;
        if (trees == null) return; // defensive — only reached in tests without a compile context
        new Walker(trees, methodPath.path(), ctx).scan(body, null);
    }

    // ── pure helpers (unit-testable) ─────────────────────────────────────

    /**
     * Decide the coercion needed when the argument expression's "is-Ptr" flag and the target
     * parameter's "is-Ptr" flag are known.
     *
     * <table>
     *   <caption>Coercion table</caption>
     *   <tr><th>arg type</th><th>param type</th><th>verdict</th></tr>
     *   <tr><td>{@code X}</td>      <td>{@code Ptr<X>}</td><td>{@link Coercion#TAKE_ADDRESS}</td></tr>
     *   <tr><td>{@code Ptr<X>}</td><td>{@code X}</td>      <td>{@link Coercion#DEREFERENCE}</td></tr>
     *   <tr><td>both same shape</td><td colspan="2">{@link Coercion#NONE}</td></tr>
     * </table>
     */
    public static Coercion classifyCoercion(boolean argIsPtr, boolean paramIsPtr) {
        if (argIsPtr == paramIsPtr) return Coercion.NONE;
        return paramIsPtr ? Coercion.TAKE_ADDRESS : Coercion.DEREFERENCE;
    }

    /**
     * Region rule from plan §"Stage 6 specification". Returns true when the expression's region
     * is compatible with the parameter's region for inserting an automatic {@code &} or
     * {@code *}. {@code UNKNOWN} on the param side always proceeds (it inherits the expression's
     * region).
     */
    public static boolean regionAllowsCoercion(MemoryRegion exprRegion, MemoryRegion paramRegion) {
        if (exprRegion == MemoryRegion.CONFLICT) return false; // already an error elsewhere
        if (paramRegion == MemoryRegion.UNKNOWN) return true;
        if (exprRegion == paramRegion) return true;
        return switch (exprRegion) {
            case STACK -> paramRegion != MemoryRegion.USER && paramRegion != MemoryRegion.ARENA;
            case KERNEL_TRACKED -> paramRegion == MemoryRegion.KERNEL_TRACKED
                    || paramRegion == MemoryRegion.KERNEL_UNTRACKED;
            case KERNEL_UNTRACKED -> paramRegion == MemoryRegion.KERNEL_UNTRACKED;
            case USER -> paramRegion == MemoryRegion.USER;
            case MAP_VALUE -> paramRegion == MemoryRegion.KERNEL_TRACKED;
            case ARENA -> paramRegion == MemoryRegion.ARENA;
            case PACKET -> paramRegion == MemoryRegion.KERNEL_TRACKED;
            case UNKNOWN, CONFLICT -> false;
        };
    }

    /** True if the type-mirror is {@code Ptr<...>} (or a subtype/raw form thereof). */
    public static boolean isPtrType(TypeMirror t) {
        if (t == null || t.getKind() != TypeKind.DECLARED) return false;
        var dt = (DeclaredType) t;
        var el = dt.asElement();
        return el.toString().equals(PTR_TYPE);
    }

    // ── AST walker ───────────────────────────────────────────────────────

    private static final class Walker extends TreeScanner<Void, Void> {
        private final Trees trees;
        private final TreePath methodPath;
        private final AnalysisContext ctx;

        Walker(Trees trees, TreePath methodPath, AnalysisContext ctx) {
            this.trees = trees;
            this.methodPath = methodPath;
            this.ctx = ctx;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            super.visitMethodInvocation(node, unused);
            var element = trees.getElement(currentPath(node));
            if (!(element instanceof ExecutableElement exec)) return null;
            var params = exec.getParameters();
            var args = node.getArguments();
            int n = Math.min(params.size(), args.size());
            for (int i = 0; i < n; i++) {
                var param = params.get(i);
                if (hasPassByRef(param)) continue;
                var arg = args.get(i);
                var coercion = decide(arg, param);
                if (coercion != Coercion.NONE) ctx.put(COERCE, arg, coercion);
            }
            return null;
        }

        @Override
        public Void visitVariable(VariableTree node, Void unused) {
            super.visitVariable(node, unused);
            var init = node.getInitializer();
            if (init == null) return null;
            var paramType = trees.getTypeMirror(new TreePath(currentPath(node), node.getType()));
            if (paramType == null) return null;
            var argType = trees.getTypeMirror(new TreePath(currentPath(node), init));
            if (argType == null) return null;
            var coercion = classifyCoercion(isPtrType(argType), isPtrType(paramType));
            if (coercion != Coercion.NONE) {
                var exprRegion = ctx.regionOf(init);
                var paramRegion = MemoryRegion.UNKNOWN; // local declaration — no seed
                if (regionAllowsCoercion(exprRegion, paramRegion)) {
                    ctx.put(COERCE, init, coercion);
                }
            }
            return null;
        }

        @Override
        public Void visitAssignment(AssignmentTree node, Void unused) {
            super.visitAssignment(node, unused);
            var lhsPath = new TreePath(currentPath(node), node.getVariable());
            var rhsPath = new TreePath(currentPath(node), node.getExpression());
            var lhsType = trees.getTypeMirror(lhsPath);
            var rhsType = trees.getTypeMirror(rhsPath);
            if (lhsType == null || rhsType == null) return null;
            var coercion = classifyCoercion(isPtrType(rhsType), isPtrType(lhsType));
            if (coercion != Coercion.NONE) {
                var exprRegion = ctx.regionOf(node.getExpression());
                var paramRegion = ctx.regionOf(node.getVariable());
                if (regionAllowsCoercion(exprRegion, paramRegion)) {
                    ctx.put(COERCE, node.getExpression(), coercion);
                }
            }
            return null;
        }

        private Coercion decide(ExpressionTree arg, VariableElement param) {
            var argType = trees.getTypeMirror(new TreePath(methodPath, arg));
            var paramType = param.asType();
            var coercion = classifyCoercion(isPtrType(argType), isPtrType(paramType));
            if (coercion == Coercion.NONE) return Coercion.NONE;
            var exprRegion = ctx.regionOf(arg);
            var paramRegion = paramRegionOf(param);
            return regionAllowsCoercion(exprRegion, paramRegion) ? coercion : Coercion.NONE;
        }

        private TreePath currentPath(Tree node) {
            var tp = trees.getPath(methodPath.getCompilationUnit(), node);
            return tp != null ? tp : new TreePath(methodPath, node);
        }

        /** Map a parameter annotation (e.g. {@code @BPFKernelMemory}) to its declared region. */
        private static MemoryRegion paramRegionOf(VariableElement param) {
            for (var ann : param.getAnnotationMirrors()) {
                var name = ann.getAnnotationType().toString();
                switch (name) {
                    case "me.bechberger.ebpf.annotations.BPFKernelMemory" -> {
                        return MemoryRegion.KERNEL_UNTRACKED;
                    }
                    case "me.bechberger.ebpf.annotations.BPFUserMemory" -> {
                        return MemoryRegion.USER;
                    }
                }
            }
            return MemoryRegion.UNKNOWN;
        }

        private static boolean hasPassByRef(VariableElement param) {
            for (AnnotationMirror ann : param.getAnnotationMirrors()) {
                if (ann.getAnnotationType().toString().equals(PASS_BY_REF_ANNOTATION)) return true;
            }
            return false;
        }
    }
}
