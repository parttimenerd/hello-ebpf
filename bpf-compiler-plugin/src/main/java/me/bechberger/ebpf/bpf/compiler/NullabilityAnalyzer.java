package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.annotations.BPFNullable;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;
import me.bechberger.ebpf.bpf.compiler.flow.NullabilityValue;

import java.util.HashMap;
import java.util.Map;

/**
 * Intra-procedural nullability analysis for BPF method bodies.
 *
 * <p>Runs a single forward pass over each BPF function body. For each variable,
 * it tracks a {@link NullabilityValue}: whether the variable is definitely not null
 * ({@code NON_NULL}), potentially null ({@code MAYBE_NULL}), or unknown ({@code UNKNOWN}).
 *
 * <p>Sources of {@code MAYBE_NULL}: calls to methods annotated with {@link BPFNullable}.
 *
 * <p>Dereferences (member access, method calls on the result) on {@code MAYBE_NULL} variables
 * are reported as compile errors unless a preceding {@code if (x != null)} narrowed them to
 * {@code NON_NULL}.
 *
 * <p>This is a single-pass analysis; it does not iterate to a fixpoint. eBPF programs are
 * small and loop-free (the verifier rejects loops), so a single pass is sufficient.
 */
public class NullabilityAnalyzer {

    /** A single detected nullability violation. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    /** Nullability state per local variable name at the current program point. */
    private final Map<String, NullabilityValue> state = new HashMap<>();

    /**
     * Pure detection: run nullability analysis on {@code method} and return every violation
     * without needing a live {@link CompilerPlugin}. Suppression-agnostic. For unit testing.
     */
    public static java.util.List<Detection> detect(MethodTree method) {
        var detections = new java.util.ArrayList<Detection>();
        var collector = new NullabilityAnalyzer(null, null, new AnalysisContext()) {
            @Override
            void reportNullable(Tree at, String varName) {
                String msg = "Potentially null pointer '" + varName + "' used in member access.\n"
                           + "Why: the BPF verifier rejects any dereference of a value that may be NULL.\n"
                           + "Fix: guard with if (" + varName + " == null) return 0;\n"
                           + "See: cookbook §Nullability";
                detections.add(new Detection(at, "nullability.deref-of-nullable", msg));
            }
        };
        var body = method.getBody();
        if (body != null) collector.analyzeBlock(body, new HashMap<>());
        return detections;
    }

    public NullabilityAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this(compilerPlugin, methodPath, new AnalysisContext());
    }

    public NullabilityAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                               AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    /** Run the analysis. Errors are reported via {@link CompilerPlugin#logError}. */
    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body != null) {
            analyzeBlock(body, new HashMap<>());
        }
    }

    private void analyzeBlock(BlockTree block, Map<String, NullabilityValue> env) {
        for (var stmt : block.getStatements()) {
            analyzeStatement(stmt, env);
        }
    }

    private void analyzeStatement(StatementTree stmt, Map<String, NullabilityValue> env) {
        switch (stmt) {
            case VariableTree varTree -> {
                var init = varTree.getInitializer();
                if (init != null) {
                    var val = analyzeExpression(init, env);
                    env.put(varTree.getName().toString(), val);
                } else {
                    env.put(varTree.getName().toString(), NullabilityValue.UNKNOWN);
                }
            }
            case ExpressionStatementTree exprStmt -> {
                var expr = exprStmt.getExpression();
                if (expr instanceof AssignmentTree assign) {
                    var val = analyzeExpression(assign.getExpression(), env);
                    if (assign.getVariable() instanceof IdentifierTree id) {
                        env.put(id.getName().toString(), val);
                    }
                } else {
                    analyzeExpression(expr, env);
                }
            }
            case IfTree ifTree -> analyzeIf(ifTree, env);
            case BlockTree blockTree -> analyzeBlock(blockTree, env);
            case ReturnTree retTree -> {
                if (retTree.getExpression() != null) {
                    analyzeExpression(retTree.getExpression(), env);
                }
            }
            case ForLoopTree forLoop -> {
                // init statements
                for (var init : forLoop.getInitializer()) {
                    analyzeStatement(init, env);
                }
                if (forLoop.getCondition() != null) analyzeExpression(forLoop.getCondition(), env);
                analyzeStatement(forLoop.getStatement(), new HashMap<>(env));
                for (var update : forLoop.getUpdate()) analyzeStatement(update, env);
            }
            case WhileLoopTree whileLoop -> {
                if (whileLoop.getCondition() != null) analyzeExpression(whileLoop.getCondition(), env);
                analyzeStatement(whileLoop.getStatement(), new HashMap<>(env));
            }
            default -> { /* other statements: break, continue, etc. — no nullability impact */ }
        }
    }

    private void analyzeIf(IfTree ifTree, Map<String, NullabilityValue> env) {
        var cond = ifTree.getCondition();
        // Unwrap parenthesized condition (JavaC wraps conditions in JCParens)
        while (cond instanceof ParenthesizedTree paren) {
            cond = paren.getExpression();
        }

        // Collect all `x != null` / `x == null` bindings from a flat &&-chain.
        // thenNonNull: variables narrowed to NON_NULL in the then-branch.
        // elseNonNull: variables narrowed to NON_NULL in the else-branch.
        var thenNonNull = new java.util.HashSet<String>();
        var elseNonNull = new java.util.HashSet<String>();
        collectNullChecks(cond, thenNonNull, elseNonNull);

        boolean hasNullCheck = !thenNonNull.isEmpty() || !elseNonNull.isEmpty();

        if (hasNullCheck) {
            var thenEnv = new HashMap<>(env);
            var elseEnv = new HashMap<>(env);
            for (var v : thenNonNull) thenEnv.put(v, NullabilityValue.NON_NULL);
            for (var v : elseNonNull) elseEnv.put(v, NullabilityValue.NON_NULL);
            analyzeStatement(ifTree.getThenStatement(), thenEnv);
            if (ifTree.getElseStatement() != null) {
                analyzeStatement(ifTree.getElseStatement(), elseEnv);
            }
            // After the if: join both branches — but if a branch always exits (return / throw),
            // it cannot fall through, so the post-if env should reflect only the surviving
            // branch. This is what makes `if (p == null) return; p.field;` safe: the then-branch
            // exits, so post-if env keeps the else-branch's NON_NULL narrowing.
            boolean thenExits = alwaysExits(ifTree.getThenStatement());
            boolean elseExits = ifTree.getElseStatement() != null
                    && alwaysExits(ifTree.getElseStatement());
            var joined = new HashMap<>(env);
            if (thenExits && elseExits) {
                // Both branches exit — code after the if is unreachable. Conservative: keep env as-is.
                env.putAll(joined);
                return;
            }
            if (thenExits) {
                env.putAll(elseEnv);
                return;
            }
            if (elseExits) {
                env.putAll(thenEnv);
                return;
            }
            var allKeys = new java.util.HashSet<String>(thenEnv.keySet());
            allKeys.addAll(elseEnv.keySet());
            for (var key : allKeys) {
                var thenVal = thenEnv.getOrDefault(key, NullabilityValue.UNKNOWN);
                var elseVal = elseEnv.getOrDefault(key, NullabilityValue.UNKNOWN);
                joined.put(key, NullabilityValue.UNKNOWN.join(thenVal, elseVal));
            }
            env.putAll(joined);
        } else {
            // No null check detected — analyze both branches with the same env
            analyzeStatement(ifTree.getThenStatement(), new HashMap<>(env));
            if (ifTree.getElseStatement() != null) {
                analyzeStatement(ifTree.getElseStatement(), new HashMap<>(env));
            }
        }
    }

    /**
     * Recursively collect null-check bindings from a condition tree.
     *
     * <p>Handles:
     * <ul>
     *   <li>{@code x != null} → thenNonNull(x)</li>
     *   <li>{@code x == null} → elseNonNull(x)</li>
     *   <li>{@code A && B} → union of both sides' then-bindings in thenNonNull</li>
     *   <li>parenthesized forms</li>
     * </ul>
     *
     * <p>Note: {@code ||} chains are intentionally not handled here — they would narrow only
     * when both sides agree, which is the minority case and complex to express; leave as
     * UNKNOWN so the analyzer is conservatively safe.
     */
    private static void collectNullChecks(ExpressionTree cond,
                                          java.util.Set<String> thenNonNull,
                                          java.util.Set<String> elseNonNull) {
        while (cond instanceof ParenthesizedTree paren) cond = paren.getExpression();
        if (cond instanceof BinaryTree bin) {
            var kind = bin.getKind();
            if (kind == Tree.Kind.CONDITIONAL_AND) {
                // Both sides must hold in then-branch; only union then-narrowings.
                collectNullChecks(bin.getLeftOperand(), thenNonNull, new java.util.HashSet<>());
                collectNullChecks(bin.getRightOperand(), thenNonNull, new java.util.HashSet<>());
                return;
            }
            if (kind == Tree.Kind.NOT_EQUAL_TO || kind == Tree.Kind.EQUAL_TO) {
                String varName = null;
                if (bin.getRightOperand() instanceof LiteralTree lit && lit.getValue() == null) {
                    if (bin.getLeftOperand() instanceof IdentifierTree id) varName = id.getName().toString();
                } else if (bin.getLeftOperand() instanceof LiteralTree lit && lit.getValue() == null) {
                    if (bin.getRightOperand() instanceof IdentifierTree id) varName = id.getName().toString();
                }
                if (varName != null) {
                    if (kind == Tree.Kind.NOT_EQUAL_TO) thenNonNull.add(varName);
                    else elseNonNull.add(varName);
                }
            }
        }
    }

    /**
     * True if {@code stmt} unconditionally transfers control out of the enclosing block
     * (return, throw, or a block whose last reachable statement does so). Used by
     * {@link #analyzeIf} to skip joining an unreachable post-branch env.
     *
     * <p>Package-private for testing.
     */
    static boolean alwaysExits(StatementTree stmt) {
        if (stmt == null) return false;
        return switch (stmt) {
            case ReturnTree r -> true;
            case ThrowTree t -> true;
            case BlockTree b -> {
                // A block always exits if any statement in it always exits — the rest is dead.
                for (var s : b.getStatements()) {
                    if (alwaysExits(s)) yield true;
                }
                yield false;
            }
            case IfTree i -> i.getElseStatement() != null
                    && alwaysExits(i.getThenStatement())
                    && alwaysExits(i.getElseStatement());
            default -> false;
        };
    }

    /**
     * Analyze an expression for nullability.
     *
     * @return the nullability of the expression's result
     */
    private NullabilityValue analyzeExpression(ExpressionTree expr, Map<String, NullabilityValue> env) {
        NullabilityValue v = switch (expr) {
            case IdentifierTree id -> env.getOrDefault(id.getName().toString(), NullabilityValue.UNKNOWN);
            case MethodInvocationTree call -> analyzeMethodCall(call, env);
            case MemberSelectTree select -> {
                // x.field or x.method() — if x is MAYBE_NULL, this is unsafe
                var recv = select.getExpression();
                checkNotNullable(recv, env, "member access");
                yield NullabilityValue.UNKNOWN;
            }
            case AssignmentTree assign -> {
                var val = analyzeExpression(assign.getExpression(), env);
                if (assign.getVariable() instanceof IdentifierTree id) {
                    env.put(id.getName().toString(), val);
                }
                yield val;
            }
            case BinaryTree bin -> {
                analyzeExpression(bin.getLeftOperand(), env);
                analyzeExpression(bin.getRightOperand(), env);
                yield NullabilityValue.UNKNOWN;
            }
            case LiteralTree lit -> lit.getValue() == null ? NullabilityValue.MAYBE_NULL : NullabilityValue.NON_NULL;
            case ParenthesizedTree paren -> analyzeExpression(paren.getExpression(), env);
            case ConditionalExpressionTree cond -> {
                analyzeExpression(cond.getCondition(), env);
                var t = analyzeExpression(cond.getTrueExpression(), env);
                var f = analyzeExpression(cond.getFalseExpression(), env);
                yield t.join(t, f);
            }
            default -> NullabilityValue.UNKNOWN;
        };
        ctx.nullAt.put(expr, v);
        return v;
    }

    private NullabilityValue analyzeMethodCall(MethodInvocationTree call, Map<String, NullabilityValue> env) {
        // Check the receiver for null-safety
        var methodSel = call.getMethodSelect();
        if (methodSel instanceof MemberSelectTree select) {
            checkNotNullable(select.getExpression(), env, "method call");
        }
        // Analyze arguments
        for (var arg : call.getArguments()) {
            analyzeExpression(arg, env);
        }
        // Check if the called method is @BPFNullable
        var symbol = getMethodSymbol(call);
        if (symbol != null && symbol.getAnnotation(BPFNullable.class) != null) {
            return NullabilityValue.MAYBE_NULL;
        }
        // Auto-seed MAYBE_NULL for any expression whose region is MAP_VALUE — populated by RegionAnalyzer.
        if (ctx.regionOf(call) == MemoryRegion.MAP_VALUE) {
            return NullabilityValue.MAYBE_NULL;
        }
        return NullabilityValue.UNKNOWN;
    }

    /**
     * Overridable hook for reporting a MAYBE_NULL dereference. The default implementation
     * calls {@link CompilerPlugin#logError}; the pure-detection subclass in
     * {@link #detect(MethodTree)} overrides this to collect {@link Detection} records instead.
     */
    void reportNullable(Tree at, String varName) {
        if (compilerPlugin == null) return;
        compilerPlugin.logError(methodPath, at,
                "Potentially null pointer '" + varName + "' used in member access.\n"
              + "Why: the BPF verifier rejects any dereference of a value that may be NULL. "
              + "Helpers like bpf_map_lookup_elem return NULL on miss; the verifier tracks "
              + "this and refuses to load programs that skip the check.\n"
              + "Fix: guard the use:\n"
              + "  if (" + varName + " == null) return 0;\n"
              + "  /* now safe to use " + varName + " */\n"
              + "See: cookbook §Nullability");
    }

    /** Emit an error if the expression resolves to a MAYBE_NULL variable. */
    private void checkNotNullable(ExpressionTree expr, Map<String, NullabilityValue> env, String context) {
        if (expr instanceof IdentifierTree id) {
            var val = env.getOrDefault(id.getName().toString(), NullabilityValue.UNKNOWN);
            if (val == NullabilityValue.MAYBE_NULL) {
                reportNullable(expr, id.getName().toString());
            }
        }
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
