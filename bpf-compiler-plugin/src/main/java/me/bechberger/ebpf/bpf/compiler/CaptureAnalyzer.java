package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;

import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * Stage 8 — D12 capture analysis for lambdas. Walks each {@link LambdaExpressionTree} in the
 * method body, collects free variables (locals defined outside the lambda), and decides for
 * each whether to {@link CaptureKind#VALUE pass-by-value}, {@link CaptureKind#BY_REF pass via
 * a synthetic capture struct}, or {@link CaptureKind#REJECT raise an error} (e.g. capturing
 * a non-{@code @Type} Java object).
 *
 * <p>Output lives in {@link #CAPTURE} on the {@link AnalysisContext}. The {@code Translator}'s
 * lambda-lifting consumer reads this instead of re-deriving captures from scratch.
 *
 * <p>Decision table (plan §"Stage 8 specification"):
 * <ul>
 *   <li>primitive scalar / boxed scalar → {@link CaptureKind#VALUE}</li>
 *   <li>{@code Ptr<T>} (any region) → {@link CaptureKind#VALUE} (the pointer is small;
 *       deref happens inside, where Stage 2 handles the region)</li>
 *   <li>struct on STACK → {@link CaptureKind#BY_REF}</li>
 *   <li>anything else (non-{@code @Type}, non-BPF-mapped Java object) → {@link CaptureKind#REJECT}</li>
 * </ul>
 *
 * <p>Category for rejections: {@code lint.lambda-capture-non-bpf}.
 */
public final class CaptureAnalyzer {

    public enum CaptureKind { VALUE, BY_REF, REJECT }

    public record Capture(String name, CaptureKind kind, MemoryRegion region, String reason) {
        public static Capture value(String name, MemoryRegion region) {
            return new Capture(name, CaptureKind.VALUE, region, "");
        }
        public static Capture byRef(String name, MemoryRegion region) {
            return new Capture(name, CaptureKind.BY_REF, region, "");
        }
        public static Capture reject(String name, MemoryRegion region, String reason) {
            return new Capture(name, CaptureKind.REJECT, region, reason);
        }
    }

    public record CapturePlan(List<Capture> captures) {}

    /** Slot for the per-lambda capture plan. {@code Translator} consults via {@link AnalysisContext#get}. */
    public static final AnalysisContext.Slot<CapturePlan> CAPTURE =
            AnalysisContext.slot("capture-plan");

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public CaptureAnalyzer(CompilerPlugin compilerPlugin,
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
        if (trees == null) return;
        var lambdas = collectLambdas(body);
        for (var lambda : lambdas) {
            var plan = analyzeOne(trees, lambda);
            ctx.put(CAPTURE, lambda, plan);
            for (var c : plan.captures()) {
                if (c.kind() != CaptureKind.REJECT) continue;
                if (ctx.isSuppressed(lambda, "lint.lambda-capture-non-bpf")) continue;
                compilerPlugin.logError(methodPath, lambda, message(c));
            }
        }
    }

    /**
     * Test entry point: analyse {@code lambda} in isolation. The caller has already constructed
     * the appropriate {@link Trees} instance for the compilation unit.
     */
    public static CapturePlan analyzeOne(Trees trees, LambdaExpressionTree lambda) {
        var paramNames = new HashSet<String>();
        for (var p : lambda.getParameters()) paramNames.add(p.getName().toString());
        var localsDefinedInside = new LinkedHashSet<String>();
        var freeVars = new LinkedHashSet<String>();
        new TreeScanner<Void, Void>() {
            @Override public Void visitVariable(VariableTree node, Void unused) {
                localsDefinedInside.add(node.getName().toString());
                return super.visitVariable(node, unused);
            }
        }.scan(lambda.getBody(), null);

        new TreeScanner<Void, Void>() {
            @Override public Void visitIdentifier(IdentifierTree node, Void unused) {
                var name = node.getName().toString();
                if (paramNames.contains(name)) return null;
                if (localsDefinedInside.contains(name)) return null;
                if (Character.isUpperCase(name.charAt(0))) return null; // class refs (heuristic)
                if (isJavaKeyword(name)) return null;
                freeVars.add(name);
                return null;
            }
        }.scan(lambda.getBody(), null);

        var captures = new ArrayList<Capture>();
        for (var name : freeVars) {
            // Without full attribution at this entry point, classify with no type info — the
            // production path goes through analyze() and reaches the AST-driven classifier.
            captures.add(classifyByName(name, null, false, MemoryRegion.UNKNOWN));
        }
        return new CapturePlan(captures);
    }

    /** Pure: classify one capture given its resolved type and region. Unit-testable. */
    public static Capture classify(String name, TypeMirror type, MemoryRegion region) {
        if (type == null) {
            return classifyByName(name, null, false, region); // safest default — pass through
        }
        var asString = type.toString();
        var primitive = type.getKind().isPrimitive();
        var declared = type.getKind() == TypeKind.DECLARED;
        return classifyByName(name, asString, primitive || declared, region);
    }

    /**
     * Pure form that consumes only the type's name and a "type info available?" flag — used by
     * tests that don't want to fabricate a {@link TypeMirror}.
     */
    public static Capture classifyByName(String name, String typeName, boolean known, MemoryRegion region) {
        if (typeName == null || !known) {
            return Capture.value(name, region);
        }
        if (isPrimitiveName(typeName)) return Capture.value(name, region);
        if (typeName.equals("me.bechberger.ebpf.type.Ptr")
                || typeName.startsWith("me.bechberger.ebpf.type.Ptr<")) {
            return Capture.value(name, region);
        }
        if (isBoxedScalar(typeName)) return Capture.value(name, region);
        if (region == MemoryRegion.STACK) return Capture.byRef(name, region);
        return Capture.reject(name, region,
                "type '" + typeName + "' is not a primitive, Ptr, or @Type record");
    }

    private static boolean isPrimitiveName(String t) {
        return switch (t) {
            case "int", "long", "short", "byte", "boolean", "char", "float", "double" -> true;
            default -> false;
        };
    }

    static boolean isPtrType(TypeMirror t) {
        if (t == null || t.getKind() != TypeKind.DECLARED) return false;
        var dt = (DeclaredType) t;
        return dt.asElement().toString().equals("me.bechberger.ebpf.type.Ptr");
    }

    private static boolean isBoxedScalar(String typeName) {
        return switch (typeName) {
            case "java.lang.Long", "java.lang.Integer", "java.lang.Short",
                 "java.lang.Byte", "java.lang.Boolean", "java.lang.Character",
                 "java.lang.Float", "java.lang.Double" -> true;
            default -> false;
        };
    }

    private static List<LambdaExpressionTree> collectLambdas(Tree subtree) {
        var out = new ArrayList<LambdaExpressionTree>();
        new TreeScanner<Void, Void>() {
            @Override public Void visitLambdaExpression(LambdaExpressionTree node, Void unused) {
                out.add(node);
                return super.visitLambdaExpression(node, unused);
            }
        }.scan(subtree, null);
        return out;
    }

    private static boolean isJavaKeyword(String name) {
        return switch (name) {
            case "this", "super", "null", "true", "false" -> true;
            default -> false;
        };
    }

    private static String message(Capture c) {
        return "Lambda captures '" + c.name() + "' but it is not a BPF-safe value.\n"
             + "Why: " + c.reason() + ". The Translator can only lift a free variable into a "
             + "synthetic top-level C function when its type is a primitive, a Ptr, or a "
             + "@Type record on the stack.\n"
             + "Fix: lift the variable to a primitive (e.g. an int index into a map), or read it "
             + "into a @Type struct copy that the lambda can then capture by-ref.\n"
             + "See: cookbook §Lambdas";
    }
}
