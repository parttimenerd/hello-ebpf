package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.annotations.BPFNullable;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
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

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;

    /** Nullability state per local variable name at the current program point. */
    private final Map<String, NullabilityValue> state = new HashMap<>();

    public NullabilityAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
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

        // Detect the pattern `if (x != null)` or `if (x == null)`
        String nullCheckedVar = null;
        boolean checkedForNonNull = false; // true means then-branch is non-null, false means else-branch

        if (cond instanceof BinaryTree bin) {
            var kind = bin.getKind();
            if (kind == Tree.Kind.NOT_EQUAL_TO || kind == Tree.Kind.EQUAL_TO) {
                String varName = null;
                boolean rightIsNull = false;
                if (bin.getRightOperand() instanceof LiteralTree lit && lit.getValue() == null) {
                    // x != null or x == null (right side is null)
                    if (bin.getLeftOperand() instanceof IdentifierTree id) {
                        varName = id.getName().toString();
                        rightIsNull = true;
                    }
                } else if (bin.getLeftOperand() instanceof LiteralTree lit && lit.getValue() == null) {
                    // null != x or null == x (left side is null)
                    if (bin.getRightOperand() instanceof IdentifierTree id) {
                        varName = id.getName().toString();
                        rightIsNull = true;
                    }
                }
                if (varName != null && rightIsNull) {
                    nullCheckedVar = varName;
                    checkedForNonNull = (kind == Tree.Kind.NOT_EQUAL_TO);
                }
            }
        }

        if (nullCheckedVar != null) {
            // then-branch env
            var thenEnv = new HashMap<>(env);
            // else-branch env
            var elseEnv = new HashMap<>(env);
            if (checkedForNonNull) {
                thenEnv.put(nullCheckedVar, NullabilityValue.NON_NULL);
            } else {
                elseEnv.put(nullCheckedVar, NullabilityValue.NON_NULL);
            }
            analyzeStatement(ifTree.getThenStatement(), thenEnv);
            if (ifTree.getElseStatement() != null) {
                analyzeStatement(ifTree.getElseStatement(), elseEnv);
            }
            // After the if: join both branches — use the more conservative value
            var joined = new HashMap<>(env);
            for (var key : thenEnv.keySet()) {
                var thenVal = thenEnv.getOrDefault(key, NullabilityValue.UNKNOWN);
                var elseVal = elseEnv.getOrDefault(key, NullabilityValue.UNKNOWN);
                joined.put(key, thenVal.join(thenVal, elseVal));
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
     * Analyze an expression for nullability.
     *
     * @return the nullability of the expression's result
     */
    private NullabilityValue analyzeExpression(ExpressionTree expr, Map<String, NullabilityValue> env) {
        return switch (expr) {
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
        return NullabilityValue.UNKNOWN;
    }

    /** Emit an error if the expression resolves to a MAYBE_NULL variable. */
    private void checkNotNullable(ExpressionTree expr, Map<String, NullabilityValue> env, String context) {
        if (expr instanceof IdentifierTree id) {
            var val = env.getOrDefault(id.getName().toString(), NullabilityValue.UNKNOWN);
            if (val == NullabilityValue.MAYBE_NULL) {
                compilerPlugin.logError(methodPath, expr,
                        "Potentially null pointer '" + id.getName() + "' used in " + context
                                + " without a null check. Guard with: if (" + id.getName() + " != null) { ... }");
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
