package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Stage 7 — D5 sub-check #2: warn when a method's local stack autos sum to a heuristic budget.
 *
 * <p>The BPF verifier enforces a 512-byte stack frame. Java code that declares many large
 * structs on the stack — or, post Stage 2, has many auto-emitted {@code T __v;} probe-read
 * destinations — bumps into that ceiling silently and rejects at load time.
 *
 * <p>This pass estimates the stack footprint per method by summing the byte-size of each
 * declared local. Sizes:
 * <ul>
 *   <li>{@code @Size(N)} on a {@code byte[]} / {@code String} → {@code N}</li>
 *   <li>Primitive scalars: long/double=8, int/float=4, short/char=2, byte/boolean=1</li>
 *   <li>Anything else: 8 (pointer-shaped, conservative under-estimate)</li>
 * </ul>
 *
 * <p>Thresholds per plan §"Risks 9": warn at 75% (≥ 384 B), error at 100% × 1.20 padding margin
 * (≥ 614 B). Aliased to plain {@code WARNING} until samples confirm the heuristic is accurate.
 *
 * <p>Category: {@code bounds.stack-budget}.
 */
public final class StackBudgetPass {

    public static final int WARN_THRESHOLD_BYTES = 384;     // 75% of 512
    public static final int ERROR_THRESHOLD_BYTES = 614;    // 512 × 1.20 padding margin

    public record Detection(Tree at, String category, String message, boolean error) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public StackBudgetPass(CompilerPlugin compilerPlugin,
                           TypedTreePath<MethodTree> methodPath,
                           AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;
        for (var d : detect(method)) {
            if (ctx.isSuppressed(d.at(), d.category())) continue;
            if (d.error()) compilerPlugin.logError(methodPath, d.at(), d.message());
            else compilerPlugin.logWarning(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection: returns at most one diagnostic per method (the threshold breach). */
    public static List<Detection> detect(MethodTree method) {
        var body = method.getBody();
        var out = new ArrayList<Detection>();
        if (body == null) return out;
        long total = sumLocalStackBytes(body);
        if (total >= ERROR_THRESHOLD_BYTES) {
            out.add(new Detection(method, "bounds.stack-budget", message(total, true), true));
        } else if (total >= WARN_THRESHOLD_BYTES) {
            out.add(new Detection(method, "bounds.stack-budget", message(total, false), false));
        }
        return out;
    }

    /** Sum the estimated byte size of every declared local in {@code body}. */
    static long sumLocalStackBytes(Tree body) {
        var totals = new long[1];
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitVariable(VariableTree node, Void unused) {
                totals[0] += estimateBytes(node);
                return super.visitVariable(node, unused);
            }

            @Override
            public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
                // Lambda bodies are emitted as separate synthetic BPF functions; their locals
                // live on a separate stack frame and must not be counted here.
                return null;
            }
        }.scan(body, null);
        return totals[0];
    }

    /** Best-effort byte estimate for a single local declaration. */
    static int estimateBytes(VariableTree var) {
        var size = SizeInference.inferSize(var);
        if (size.isPresent() && size.getAsInt() > 0) return size.getAsInt();
        var typeStr = simpleTypeName(var.getType());
        return switch (typeStr) {
            case "long", "double", "Long", "Double" -> 8;
            case "int", "float", "Integer", "Float" -> 4;
            case "short", "char", "Short", "Character" -> 2;
            case "byte", "boolean", "Byte", "Boolean" -> 1;
            default -> 8;
        };
    }

    private static String simpleTypeName(Tree type) {
        if (type == null) return "";
        if (type instanceof AnnotatedTypeTree at) return simpleTypeName(at.getUnderlyingType());
        if (type instanceof ParameterizedTypeTree pt) return simpleTypeName(pt.getType());
        if (type instanceof ArrayTypeTree at) return "array<" + simpleTypeName(at.getType()) + ">";
        if (type instanceof IdentifierTree id) return id.getName().toString();
        if (type instanceof MemberSelectTree mst) return mst.getIdentifier().toString();
        if (type instanceof PrimitiveTypeTree pt) return pt.getPrimitiveTypeKind().name().toLowerCase();
        return type.toString();
    }

    private static String message(long bytes, boolean error) {
        var verb = error ? "exceeds" : "approaches";
        return "Estimated stack footprint " + verb + " the BPF 512-byte frame limit ("
                + bytes + " bytes; threshold "
                + (error ? ERROR_THRESHOLD_BYTES : WARN_THRESHOLD_BYTES) + ").\n"
             + "Why: every BPF program runs on a fixed 512-byte stack. Large local structs / "
             + "buffers can silently push past this and the verifier will reject the program "
             + "at load time with 'invalid stack access'.\n"
             + "Fix: move large buffers to a per-CPU array or a BPFArena allocation, or split "
             + "the work across smaller functions called via tail-calls / bpf_loop.\n"
             + "See: cookbook §Stack budget";
    }
}
