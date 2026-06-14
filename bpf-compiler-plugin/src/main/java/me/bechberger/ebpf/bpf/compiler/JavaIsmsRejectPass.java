package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-pass that rejects Java patterns the BPF compiler/verifier cannot handle, with
 * 4-part error messages (what / why / fix / see). Stage 13 of the unified plan.
 *
 * <p>Runs before {@code Translator}. Each pattern below produces a category-tagged error
 * (suppressible via {@code @SuppressBPFWarning}) so users see the rejection reason at
 * javac-time instead of a cryptic verifier failure or a deep-Translator stacktrace.
 *
 * <p>Categories:
 * <ul>
 *   <li>{@code java-isms.throw} — {@code throw new ...}</li>
 *   <li>{@code java-isms.string-concat} — {@code String.format} / {@code "a"+"b"}</li>
 *   <li>{@code java-isms.optional} — {@code Optional.*}</li>
 *   <li>{@code java-isms.system-out} — {@code System.out/err.*}</li>
 *   <li>{@code java-isms.thread} — {@code Thread.*}</li>
 *   <li>{@code java-isms.random} — {@code Math.random}, {@code java.util.Random}</li>
 *   <li>{@code java-isms.assert} — {@code assert} statements</li>
 *   <li>{@code java-isms.heap-array} — {@code new T[n]} where {@code n} is non-constant</li>
 *   <li>{@code java-isms.autobox} — {@code Integer.valueOf}/{@code Long.valueOf}/etc.</li>
 * </ul>
 */
public final class JavaIsmsRejectPass {

    /** A single detected java-ism. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    public JavaIsmsRejectPass(CompilerPlugin compilerPlugin,
                              TypedTreePath<MethodTree> methodPath,
                              AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var body = methodPath.leaf().getBody();
        if (body == null) return;
        for (var d : detect(body)) {
            if (ctx.isSuppressed(d.at(), d.category())) continue;
            compilerPlugin.logError(methodPath, d.at(), d.message());
        }
    }

    /** Pure detection: walks the given subtree and returns every java-ism. Suppression-agnostic. */
    public static List<Detection> detect(Tree subtree) {
        var out = new ArrayList<Detection>();
        new Visitor(out).scan(subtree, null);
        return out;
    }

    /** Detect compile-time-constant integer expressions for {@code new T[n]} sizing. */
    private static boolean isCompileTimeConstantInt(ExpressionTree e) {
        if (e instanceof LiteralTree lit && lit.getValue() instanceof Number) return true;
        if (e instanceof IdentifierTree) return false; // safest assumption without symbols
        if (e instanceof MemberSelectTree) return false;
        if (e instanceof ParenthesizedTree p) return isCompileTimeConstantInt(p.getExpression());
        if (e instanceof UnaryTree u && (u.getKind() == Tree.Kind.UNARY_MINUS || u.getKind() == Tree.Kind.UNARY_PLUS)) {
            return isCompileTimeConstantInt(u.getExpression());
        }
        return false;
    }

    private static final class Visitor extends TreeScanner<Void, Void> {
        private final List<Detection> out;

        Visitor(List<Detection> out) { this.out = out; }

        @Override
        public Void visitThrow(ThrowTree node, Void unused) {
            out.add(new Detection(node, "java-isms.throw",
                    "'throw' is not supported in BPF programs.\n"
                  + "Why: BPF has no exception model; helpers signal failure via return values "
                  + "(often -errno or NULL).\n"
                  + "Fix: return a sentinel value (e.g. -1) and check it at the call site.\n"
                  + "See: cookbook §Error handling"));
            return super.visitThrow(node, unused);
        }

        @Override
        public Void visitAssert(AssertTree node, Void unused) {
            out.add(new Detection(node, "java-isms.assert",
                    "'assert' is not supported in BPF programs.\n"
                  + "Why: there is no JVM at runtime; assertions are stripped at compile time anyway.\n"
                  + "Fix: use 'if (!cond) return -1;' for hard rejections, or "
                  + "'bpf_printk(\"warn: ...\");' for soft warnings."));
            return super.visitAssert(node, unused);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void unused) {
            var sel = node.getMethodSelect();
            if (sel instanceof MemberSelectTree ms) {
                String method = ms.getIdentifier().toString();
                String receiver = ms.getExpression().toString();
                checkInvocation(node, receiver, method);
            }
            return super.visitMethodInvocation(node, unused);
        }

        private void checkInvocation(MethodInvocationTree node, String receiver, String method) {
            // String.format(...)
            if (receiver.equals("String") && method.equals("format")) {
                out.add(new Detection(node, "java-isms.string-concat",
                        "String.format is not supported in BPF programs.\n"
                      + "Why: it requires a heap allocator, which BPF does not provide.\n"
                      + "Fix: use 'bpf_trace_printk(\"format %s %d\", arg1, arg2)' with placeholders."));
                return;
            }
            // Optional.*
            if (receiver.equals("Optional") || receiver.endsWith(".Optional")) {
                out.add(new Detection(node, "java-isms.optional",
                        "java.util.Optional is not supported in BPF programs.\n"
                      + "Why: Optional wraps values in a heap object; BPF has no heap.\n"
                      + "Fix: use a nullable Ptr<T> (annotate with @BPFNullable) and check '== null'."));
                return;
            }
            // Math.random / Random
            if ((receiver.equals("Math") && method.equals("random"))
                    || (receiver.equals("Random") || receiver.endsWith(".Random"))) {
                out.add(new Detection(node, "java-isms.random",
                        "Math.random / java.util.Random are not supported in BPF programs.\n"
                      + "Why: non-deterministic, not available in the kernel.\n"
                      + "Fix: use 'BPFHelpers.bpf_get_prandom_u32()'."));
                return;
            }
            // Thread.*
            if (receiver.equals("Thread") || receiver.endsWith(".Thread")) {
                out.add(new Detection(node, "java-isms.thread",
                        "java.lang.Thread is not supported in BPF programs.\n"
                      + "Why: BPF runs in the kernel context that triggered the program; "
                      + "there is no current Thread.\n"
                      + "Fix: for sleeps, use BPF timers via 'bpf_timer_*' (see TimerDemo.java)."));
                return;
            }
            // System.out/err.println etc.
            if (receiver.startsWith("System.out") || receiver.startsWith("System.err")) {
                out.add(new Detection(node, "java-isms.system-out",
                        "System.out/System.err is not available in BPF programs.\n"
                      + "Why: there is no stdio in the kernel.\n"
                      + "Fix: use 'bpf_trace_printk(\"...\")' for tracing or a 'BPFRingBuffer' "
                      + "for events to userspace."));
                return;
            }
            // Boxing: Integer.valueOf(int), Long.valueOf(long), etc.
            if (method.equals("valueOf") && isBoxedNumericType(receiver)) {
                out.add(new Detection(node, "java-isms.autobox",
                        receiver + ".valueOf is not supported in BPF programs.\n"
                      + "Why: it allocates a boxed wrapper object; BPF has no heap.\n"
                      + "Fix: use the primitive directly. If you need it in a map, declare the "
                      + "map value as the primitive type (e.g. 'BPFHashMap<int, int>')."));
            }
        }

        /** Wrapper types whose {@code valueOf(primitive)} call is an allocation in standard Java. */
        private static boolean isBoxedNumericType(String receiver) {
            return switch (receiver) {
                case "Integer", "Long", "Short", "Byte", "Character", "Boolean", "Float", "Double" -> true;
                default -> receiver.startsWith("java.lang.")
                        && isBoxedNumericType(receiver.substring("java.lang.".length()));
            };
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void unused) {
            // `new Random()` / `new java.util.Random()` — the static-method case is caught in
            // visitMethodInvocation, but the constructor path also allocates and is just as bad.
            String typeStr = node.getIdentifier().toString();
            if (typeStr.equals("Random") || typeStr.endsWith(".Random")) {
                out.add(new Detection(node, "java-isms.random",
                        "java.util.Random is not supported in BPF programs.\n"
                      + "Why: requires a heap allocation and is non-deterministic.\n"
                      + "Fix: use 'BPFHelpers.bpf_get_prandom_u32()'."));
            }
            return super.visitNewClass(node, unused);
        }

        @Override
        public Void visitNewArray(NewArrayTree node, Void unused) {
            // new T[n] with non-constant n.
            for (var dim : node.getDimensions()) {
                if (dim != null && !isCompileTimeConstantInt(dim)) {
                    out.add(new Detection(node, "java-isms.heap-array",
                            "Dynamically-sized array allocation (new T[n] with non-constant n) "
                          + "is not supported in BPF programs.\n"
                          + "Why: BPF has no heap allocator; stack arrays must be a compile-time size.\n"
                          + "Fix: use '@Size(N) T[]' field with a compile-time constant N, or "
                          + "'BPFJ.bpfArenaAllocPages(...)' for dynamic-sized buffers."));
                    break;
                }
            }
            return super.visitNewArray(node, unused);
        }
    }
}
