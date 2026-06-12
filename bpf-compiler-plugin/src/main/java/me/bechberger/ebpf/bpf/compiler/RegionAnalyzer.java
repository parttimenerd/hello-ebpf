package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;

import java.util.HashMap;
import java.util.Map;

/**
 * Intra-procedural memory-region analysis for BPF method bodies (Phase 3).
 *
 * <p>Tracks the provenance of every local variable: {@link MemoryRegion#USER} (syscall
 * tracepoint arguments), {@link MemoryRegion#KERNEL} (kernel data structures),
 * {@link MemoryRegion#ARENA} ({@code @InArena} pointers), {@link MemoryRegion#MAP_VALUE}
 * (map-lookup results), or {@link MemoryRegion#UNKNOWN}.
 *
 * <p>Sources:
 * <ul>
 *   <li>Method parameters annotated with {@link BPFUserMemory} → {@code USER}</li>
 *   <li>Method parameters annotated with {@link BPFKernelMemory} → {@code KERNEL}</li>
 *   <li>Variables / parameters annotated with {@link InArena} → {@code ARENA}</li>
 *   <li>Return value of {@code bpf_get} / {@code bpf_map_lookup_elem} → {@code MAP_VALUE}</li>
 * </ul>
 *
 * <p>At every dereference site (member-select on a pointer, or {@code Ptr.val()} call) the
 * analysis checks the receiver's region and warns when USER memory is dereferenced directly —
 * the user should call {@code bpf_probe_read_user} instead.
 */
public class RegionAnalyzer {

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;

    public RegionAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
    }

    /** Run the analysis. Warnings/errors are reported via {@link CompilerPlugin#logError}. */
    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        // Seed parameter regions from annotations (AST-based check, no symbol required)
        var env = new HashMap<String, MemoryRegion>();
        for (var param : method.getParameters()) {
            env.put(param.getName().toString(), regionFromAnnotations(param));
        }

        analyzeBlock(body, env);
    }

    // ── statement visitors ────────────────────────────────────────────────

    private void analyzeBlock(BlockTree block, Map<String, MemoryRegion> env) {
        for (var stmt : block.getStatements()) {
            analyzeStatement(stmt, env);
        }
    }

    private void analyzeStatement(StatementTree stmt, Map<String, MemoryRegion> env) {
        switch (stmt) {
            case VariableTree varTree -> {
                MemoryRegion region = regionFromAnnotations(varTree);
                if (region == MemoryRegion.UNKNOWN && varTree.getInitializer() != null) {
                    region = analyzeExpression(varTree.getInitializer(), env);
                }
                env.put(varTree.getName().toString(), region);
            }
            case ExpressionStatementTree exprStmt -> {
                var expr = exprStmt.getExpression();
                if (expr instanceof AssignmentTree assign) {
                    var region = analyzeExpression(assign.getExpression(), env);
                    if (assign.getVariable() instanceof IdentifierTree id) {
                        env.put(id.getName().toString(), region);
                    }
                } else {
                    analyzeExpression(expr, env);
                }
            }
            case IfTree ifTree -> {
                analyzeExpression(ifTree.getCondition(), env);
                analyzeStatement(ifTree.getThenStatement(), new HashMap<>(env));
                if (ifTree.getElseStatement() != null) {
                    analyzeStatement(ifTree.getElseStatement(), new HashMap<>(env));
                }
            }
            case BlockTree blockTree -> analyzeBlock(blockTree, env);
            case ReturnTree retTree -> {
                if (retTree.getExpression() != null) analyzeExpression(retTree.getExpression(), env);
            }
            case ForLoopTree forLoop -> {
                for (var init : forLoop.getInitializer()) analyzeStatement(init, env);
                if (forLoop.getCondition() != null) analyzeExpression(forLoop.getCondition(), env);
                analyzeStatement(forLoop.getStatement(), new HashMap<>(env));
                for (var upd : forLoop.getUpdate()) analyzeStatement(upd, env);
            }
            case WhileLoopTree whileLoop -> {
                if (whileLoop.getCondition() != null) analyzeExpression(whileLoop.getCondition(), env);
                analyzeStatement(whileLoop.getStatement(), new HashMap<>(env));
            }
            default -> { /* no region impact */ }
        }
    }

    // ── expression visitors ───────────────────────────────────────────────

    private MemoryRegion analyzeExpression(ExpressionTree expr, Map<String, MemoryRegion> env) {
        return switch (expr) {
            case IdentifierTree id -> env.getOrDefault(id.getName().toString(), MemoryRegion.UNKNOWN);
            case MemberSelectTree select -> {
                // Dereference check: e.g. ptr.field or ptr.method()
                var recvRegion = analyzeExpression(select.getExpression(), env);
                if (recvRegion == MemoryRegion.USER) {
                    warnUserDeref(select.getExpression(), select.getIdentifier().toString());
                }
                yield MemoryRegion.UNKNOWN;
            }
            case MethodInvocationTree call -> analyzeCall(call, env);
            case AssignmentTree assign -> {
                var region = analyzeExpression(assign.getExpression(), env);
                if (assign.getVariable() instanceof IdentifierTree id) {
                    env.put(id.getName().toString(), region);
                }
                yield region;
            }
            case ParenthesizedTree paren -> analyzeExpression(paren.getExpression(), env);
            case BinaryTree bin -> {
                analyzeExpression(bin.getLeftOperand(), env);
                analyzeExpression(bin.getRightOperand(), env);
                yield MemoryRegion.UNKNOWN;
            }
            case UnaryTree unary -> analyzeExpression(unary.getExpression(), env);
            case ConditionalExpressionTree cond -> {
                analyzeExpression(cond.getCondition(), env);
                var t = analyzeExpression(cond.getTrueExpression(), env);
                var f = analyzeExpression(cond.getFalseExpression(), env);
                yield t.join(t, f);
            }
            case TypeCastTree cast -> analyzeExpression(cast.getExpression(), env);
            default -> MemoryRegion.UNKNOWN;
        };
    }

    private MemoryRegion analyzeCall(MethodInvocationTree call, Map<String, MemoryRegion> env) {
        // Check receiver
        var sel = call.getMethodSelect();
        if (sel instanceof MemberSelectTree select) {
            var recvRegion = analyzeExpression(select.getExpression(), env);
            // val() on a USER Ptr<T> is a direct deref — warn
            var methodName = select.getIdentifier().toString();
            if (recvRegion == MemoryRegion.USER && (methodName.equals("val") || methodName.equals("set"))) {
                warnUserDeref(select.getExpression(), methodName + "()");
            }
        }
        // Analyze arguments
        for (var arg : call.getArguments()) {
            analyzeExpression(arg, env);
        }
        // Classify return region
        var sym = getMethodSymbol(call);
        if (sym != null) {
            var name = sym.getSimpleName().toString();
            // bpf_get / bpf_map_lookup_elem returns MAP_VALUE (nullable Ptr<V>)
            if (name.equals("bpf_get") || name.equals("bpf_map_lookup_elem")) {
                return MemoryRegion.MAP_VALUE;
            }
        }
        return MemoryRegion.UNKNOWN;
    }

    /** Check AST annotations on a variable/parameter tree to determine its region. */
    private static MemoryRegion regionFromAnnotations(VariableTree v) {
        for (var ann : v.getModifiers().getAnnotations()) {
            var name = ann.getAnnotationType().toString();
            var simple = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
            if (simple.equals("BPFUserMemory")) return MemoryRegion.USER;
            if (simple.equals("BPFKernelMemory")) return MemoryRegion.KERNEL;
            if (simple.equals("InArena")) return MemoryRegion.ARENA;
        }
        return MemoryRegion.UNKNOWN;
    }

    private void warnUserDeref(ExpressionTree expr, String context) {
        String varName = (expr instanceof IdentifierTree id) ? id.getName().toString() : "<expr>";
        compilerPlugin.logError(methodPath, expr,
                "Direct dereference of user-memory pointer '" + varName + "' in '" + context
                        + "' may fault. Use bpf_probe_read_user(&dst, sizeof(dst), "
                        + varName + ") to safely copy from user space.");
    }

    private MethodSymbol getMethodSymbol(MethodInvocationTree call) {
        try {
            return switch (call.getMethodSelect()) {
                case com.sun.tools.javac.tree.JCTree.JCFieldAccess access -> (MethodSymbol) access.sym;
                case com.sun.tools.javac.tree.JCTree.JCIdent ident -> (MethodSymbol) ident.sym;
                default -> null;
            };
        } catch (ClassCastException e) {
            return null;
        }
    }
}
