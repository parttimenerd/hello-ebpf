package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.*;
import me.bechberger.ebpf.bpf.compiler.flow.MapLattice.Env;

import java.util.HashMap;
import java.util.Map;

/**
 * Memory-region analysis built on the monotone-dataflow framework.
 *
 * <p>Tracks the {@link MemoryRegion} of every local variable and writes the inferred region
 * of every dereferencable expression into {@link AnalysisContext#regionAt}. Subsequent passes
 * (Translator, BoundsCheckPass, ArenaAccessCheckPass) read those facts instead of re-deriving.
 *
 * <p><b>Sources</b> (plan §"Seed table"):
 * <ul>
 *   <li>Parameter annotations: {@code @BPFUserMemory} → USER, {@code @BPFKernelMemory} →
 *       KERNEL_UNTRACKED, {@code @InArena} → ARENA</li>
 *   <li>Method calls: {@code bpf_get}/{@code bpf_map_lookup_elem} → MAP_VALUE,
 *       {@code bpfArenaAllocPages} → ARENA, {@code bpf_get_current_task[_btf]} →
 *       KERNEL_UNTRACKED, packet sources ({@code xdp_md.data}/{@code data_end}) → PACKET</li>
 *   <li>Probe-read seeding: after {@code bpf_probe_read_user/kernel(dst, src)} the local
 *       {@code dst} is reseeded as STACK — this kills the double-load anti-pattern</li>
 *   <li>Casts: {@code BPFJ.castUser/castKernel/castArena} re-tag the region</li>
 *   <li>Member-select inheritance: field access on a {@code KERNEL_TRACKED} struct pointer
 *       yields {@code KERNEL_UNTRACKED} for nested struct pointers (verifier loses tracking)</li>
 * </ul>
 *
 * <p><b>Mixing</b>: when a join produces {@link MemoryRegion#CONFLICT}, the analyzer emits a
 * {@code region.mixing} error naming the assignment site (plan §"Mixing rules").
 *
 * <p><b>Backwards compatibility.</b> The class is still constructible without an
 * {@link AnalysisContext} for callers that haven't migrated yet — in that mode it builds a
 * private context and discards it.
 */
public class RegionAnalyzer {

    /** A single detected region-mixing violation. Exposed for unit testing. */
    public record Detection(Tree at, String category, String message) {}

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;
    /** Non-null only when running in pure-detection mode via {@link #detect}. */
    private final java.util.List<Detection> detectOut;
    /** Last AST site (declaration / assignment) where each variable was assigned a non-UNKNOWN
     *  region.  Populated during the second annotation pass and used by {@link #reportMixing}
     *  so the mixing error can name BOTH source sites.  Reset on each {@link #analyze()} run. */
    private final java.util.Map<String, Tree> lastRegionSite = new java.util.HashMap<>();

    public RegionAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this(compilerPlugin, methodPath, new AnalysisContext());
    }

    public RegionAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                          AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
        this.detectOut = null;
    }

    private RegionAnalyzer(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                           AnalysisContext ctx, java.util.List<Detection> detectOut) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
        this.detectOut = detectOut;
    }

    public AnalysisContext context() { return ctx; }

    /**
     * Pure detection: run region analysis on {@code method} and return every region-mixing error.
     * Does not need a live {@link CompilerPlugin}. Suppression-agnostic. For unit testing.
     *
     * <p>Also populates the returned {@link AnalysisContext}'s {@code regionAt} map so callers
     * can inspect inferred regions.
     */
    public static java.util.List<Detection> detect(MethodTree method) {
        return detect(method, new AnalysisContext());
    }

    public static java.util.List<Detection> detect(MethodTree method, AnalysisContext ctx) {
        var detections = new java.util.ArrayList<Detection>();
        var analyzer = new RegionAnalyzer(null, null, ctx, detections);
        analyzer.analyzeMethod(method);
        return detections;
    }

    /** Visible for the detect() path which needs to call analyze without a TypedTreePath. */
    private void analyzeMethod(MethodTree method) {
        if (method.getBody() == null) return;
        var tempCtx = ctx;
        if (tempCtx.cfg == null) tempCtx.cfg = ControlFlowGraph.buildFromMethod(method);
        Map<String, MemoryRegion> seed = new HashMap<>();
        for (var p : method.getParameters()) {
            seed.put(p.getName().toString(), regionFromAnnotations(p));
        }
        var lat = new MapLattice<String, MemoryRegion>(MemoryRegion.UNKNOWN);
        var transfer = new RegionTransfer(lat, seed);
        var result = MonotoneFramework.solve(tempCtx.cfg, transfer);
        for (var b : tempCtx.cfg.blocks()) {
            var env = result.inAt(b);
            var mutEnv = lat.toMutable(env);
            for (var n : b.nodes()) {
                annotateNode(n, mutEnv);
                env = transfer.transferNode(n, lat.fromMap(mutEnv));
                mutEnv = lat.toMutable(env);
            }
        }
    }



    public void analyze() {
        var method = methodPath.leaf();
        if (method.getBody() == null) return;

        // Build (or reuse) the CFG.
        if (ctx.cfg == null) ctx.cfg = ControlFlowGraph.buildFromMethod(method);

        // Seed parameter regions.
        Map<String, MemoryRegion> seed = new HashMap<>();
        for (var p : method.getParameters()) {
            seed.put(p.getName().toString(), regionFromAnnotations(p));
        }

        var lat = new MapLattice<String, MemoryRegion>(MemoryRegion.UNKNOWN);
        var transfer = new RegionTransfer(lat, seed);
        var result = MonotoneFramework.solve(ctx.cfg, transfer);

        // Second pass: re-evaluate expressions per program point with the fixpoint env to
        // populate ctx.regionAt and emit dereference/mixing diagnostics.
        for (var b : ctx.cfg.blocks()) {
            var env = result.inAt(b);
            var mutEnv = lat.toMutable(env);
            for (var n : b.nodes()) {
                annotateNode(n, mutEnv);
                env = transfer.transferNode(n, lat.fromMap(mutEnv));
                mutEnv = lat.toMutable(env);
            }
        }
    }

    // ── transfer function ────────────────────────────────────────────────

    /**
     * Forward transfer over the region environment. Implements the full seed table from
     * plan §"Seed table" and the mixing rules from plan §"Mixing rules".
     */
    private final class RegionTransfer implements TransferFunction<Env<String, MemoryRegion>> {
        private final MapLattice<String, MemoryRegion> lat;
        private final Map<String, MemoryRegion> seed;

        RegionTransfer(MapLattice<String, MemoryRegion> lat, Map<String, MemoryRegion> seed) {
            this.lat = lat;
            this.seed = seed;
        }

        @Override public Lattice<Env<String, MemoryRegion>> lattice() { return lat; }
        @Override public Env<String, MemoryRegion> initialEntry() { return lat.fromMap(seed); }

        @Override
        public Env<String, MemoryRegion> transferNode(FlowNode node, Env<String, MemoryRegion> in) {
            // Use a mutable view to apply the assignment.
            var mut = lat.toMutable(in);
            switch (node.kind) {
                case DECL -> {
                    if (node.tree instanceof VariableTree v) {
                        var declared = regionFromAnnotations(v);
                        MemoryRegion r = declared;
                        if (r == MemoryRegion.UNKNOWN && v.getInitializer() != null) {
                            r = evalExpression(v.getInitializer(), mut);
                        }
                        mut.put(v.getName().toString(), r);
                        if (r != MemoryRegion.UNKNOWN) {
                            lastRegionSite.put(v.getName().toString(), v);
                        }
                    }
                }
                case ASSIGN -> {
                    if (node.tree instanceof AssignmentTree a) {
                        var rhs = evalExpression(a.getExpression(), mut);
                        if (a.getVariable() instanceof IdentifierTree id) {
                            var name = id.getName().toString();
                            var prev = mut.getOrDefault(name, MemoryRegion.UNKNOWN);
                            var joined = MemoryRegion.UNKNOWN.join(prev, rhs);
                            if (joined == MemoryRegion.CONFLICT) {
                                reportMixing(a, name, prev, rhs);
                                joined = rhs; // recover with the RHS region
                            }
                            mut.put(name, joined);
                            if (rhs != MemoryRegion.UNKNOWN) {
                                lastRegionSite.put(name, a);
                            }
                        }
                    }
                }
                case CALL, EXPR -> {
                    if (node.tree instanceof ExpressionTree e) evalExpression(e, mut);
                }
                case BRANCH, RETURN, THROW, LAMBDA, LOOP_HEADER, MERGE -> {
                    var inner = innerExpression(node.tree);
                    if (inner != null) evalExpression(inner, mut);
                }
            }
            return lat.fromMap(mut);
        }
    }

    // ── expression evaluation ────────────────────────────────────────────

    /** Evaluate the region of an expression in the current env, with side effects (probe-read seeding). */
    private MemoryRegion evalExpression(ExpressionTree expr, Map<String, MemoryRegion> env) {
        if (expr == null) return MemoryRegion.UNKNOWN;
        MemoryRegion r = switch (expr) {
            case IdentifierTree id -> env.getOrDefault(id.getName().toString(), MemoryRegion.UNKNOWN);
            case ParenthesizedTree p -> evalExpression(p.getExpression(), env);
            case TypeCastTree cast -> evalExpression(cast.getExpression(), env);
            case ConditionalExpressionTree cond -> {
                evalExpression(cond.getCondition(), env);
                var t = evalExpression(cond.getTrueExpression(), env);
                var f = evalExpression(cond.getFalseExpression(), env);
                yield MemoryRegion.UNKNOWN.join(t, f);
            }
            case BinaryTree bin -> {
                evalExpression(bin.getLeftOperand(), env);
                evalExpression(bin.getRightOperand(), env);
                yield MemoryRegion.UNKNOWN;
            }
            case UnaryTree un -> evalExpression(un.getExpression(), env);
            case AssignmentTree a -> {
                var rhs = evalExpression(a.getExpression(), env);
                if (a.getVariable() instanceof IdentifierTree id) {
                    env.put(id.getName().toString(), rhs);
                }
                yield rhs;
            }
            case MemberSelectTree sel -> evalMemberSelect(sel, env);
            case MethodInvocationTree call -> evalCall(call, env);
            default -> MemoryRegion.UNKNOWN;
        };
        ctx.regionAt.put(expr, r);
        return r;
    }

    /**
     * Member-select region:
     * <ul>
     *   <li>{@code xdp_md.data}/{@code data_end}, {@code __sk_buff.data}/{@code data_end} → PACKET</li>
     *   <li>USER receiver → warn (legacy) and yield UNKNOWN — the Translator's auto-emit will
     *       insert a probe-read at the deref site</li>
     *   <li>KERNEL_TRACKED receiver: nested struct field → KERNEL_UNTRACKED (verifier loses
     *       tracking past one struct hop without CO-RE); primitive field → STACK</li>
     *   <li>ARENA receiver → ARENA (clang AS1 deref)</li>
     *   <li>otherwise UNKNOWN</li>
     * </ul>
     */
    private MemoryRegion evalMemberSelect(MemberSelectTree sel, Map<String, MemoryRegion> env) {
        var fieldName = sel.getIdentifier().toString();
        // Packet-context recognition: receiver is a Ptr to xdp_md / __sk_buff.
        if ((fieldName.equals("data") || fieldName.equals("data_end"))
                && receiverLooksLikePacketContext(sel.getExpression())) {
            return MemoryRegion.PACKET;
        }
        var recv = evalExpression(sel.getExpression(), env);
        if (recv == MemoryRegion.USER) {
            // Auto-probe-read takes over in the Translator; warning only fires when no auto-emit applies.
            // Keep emitting a hint here so old samples without the auto-emit still see something useful.
            warnUserDeref(sel.getExpression(), fieldName);
            return MemoryRegion.UNKNOWN;
        }
        if (recv == MemoryRegion.KERNEL_TRACKED) return MemoryRegion.KERNEL_UNTRACKED;
        if (recv == MemoryRegion.ARENA) return MemoryRegion.ARENA;
        return MemoryRegion.UNKNOWN;
    }

    private static boolean receiverLooksLikePacketContext(ExpressionTree e) {
        // Heuristic: receiver is an identifier whose name suggests a packet ctx, OR a member-select
        // ending in something whose declared type would be xdp_md/__sk_buff. Without symbol info we
        // do a syntactic match; the Translator/BoundsCheckPass refine.
        var u = e;
        while (u instanceof ParenthesizedTree p) u = p.getExpression();
        if (u instanceof IdentifierTree id) {
            var n = id.getName().toString();
            return n.equals("ctx") || n.equals("xdp") || n.equals("skb")
                    || n.endsWith("Ctx") || n.contains("packet");
        }
        return false;
    }

    private MemoryRegion evalCall(MethodInvocationTree call, Map<String, MemoryRegion> env) {
        // Receiver-side deref check (val()/set() on a USER pointer).
        var sel = call.getMethodSelect();
        String methodName = null;
        if (sel instanceof MemberSelectTree ms) {
            methodName = ms.getIdentifier().toString();
            var recv = evalExpression(ms.getExpression(), env);
            if (recv == MemoryRegion.USER && methodName.equals("val")) {
                // Auto-probe-read in Translator covers val(); demote to warning.
                warnUserDeref(ms.getExpression(), methodName + "()");
            } else if (recv == MemoryRegion.USER && methodName.equals("set")) {
                // No auto-emit for set() — writes to user memory require bpf_probe_write_user
                // (capability-gated, dangerous), so this stays an error.
                errorUserWrite(ms.getExpression(), methodName + "()");
            }
        } else if (sel instanceof IdentifierTree id) {
            methodName = id.getName().toString();
        }

        // Walk arguments first (for region annotation).
        for (var arg : call.getArguments()) evalExpression(arg, env);

        var sym = getMethodSymbol(call);
        var symName = sym == null ? null : sym.getSimpleName().toString();
        var name = symName != null ? symName : methodName;

        if (name != null) {
            // Probe-read seeding: bpf_probe_read_user/kernel[_str] (dst, src) marks dst as STACK.
            if (name.equals("bpf_probe_read_user") || name.equals("bpf_probe_read_kernel")
                    || name.equals("bpf_probe_read_user_str") || name.equals("bpf_probe_read_kernel_str")
                    || name.equals("bpf_probe_read")) {
                if (!call.getArguments().isEmpty()
                        && call.getArguments().get(0) instanceof IdentifierTree dst) {
                    env.put(dst.getName().toString(), MemoryRegion.STACK);
                }
                return MemoryRegion.UNKNOWN;
            }
            // MAP_VALUE sources.
            if (name.equals("bpf_get") || name.equals("bpf_map_lookup_elem")) return MemoryRegion.MAP_VALUE;
            // Untracked-kernel sources.
            if (name.equals("bpf_get_current_task") || name.equals("bpf_get_current_task_btf")) return MemoryRegion.KERNEL_UNTRACKED;
            // Arena allocation.
            if (name.equals("bpfArenaAllocPages")) return MemoryRegion.ARENA;
            // Casts: BPFJ.castUser / castKernel / castArena.
            if (name.equals("castUser")) return MemoryRegion.USER;
            if (name.equals("castKernel")) return MemoryRegion.KERNEL_UNTRACKED;
            if (name.equals("castArena")) return MemoryRegion.ARENA;
            // Ptr.cast: propagate receiver region.
            if (name.equals("cast") && sel instanceof MemberSelectTree ms2) {
                return evalExpression(ms2.getExpression(), env);
            }
        }
        return MemoryRegion.UNKNOWN;
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /** Inspect AST annotations on a parameter / local to derive its initial region. */
    static MemoryRegion regionFromAnnotations(VariableTree v) {
        for (var ann : v.getModifiers().getAnnotations()) {
            var name = ann.getAnnotationType().toString();
            var simple = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : name;
            switch (simple) {
                case "BPFUserMemory" -> { return MemoryRegion.USER; }
                case "BPFKernelMemory" -> { return MemoryRegion.KERNEL_UNTRACKED; }
                case "InArena" -> { return MemoryRegion.ARENA; }
            }
        }
        return MemoryRegion.UNKNOWN;
    }

    /**
     * Overridable hook for region-mixing errors. Default calls {@link CompilerPlugin#logError};
     * the pure-detection subclass in {@link #detect(MethodTree)} overrides this to collect
     * {@link Detection} records instead.
     */
    void emitMixingError(Tree at, String varName, MemoryRegion prev, MemoryRegion rhs) {
        if (detectOut != null) {
            String msg = "Cannot mix " + prev + " and " + rhs + " memory regions in '" + varName + "'.\n"
                       + "Why: BPF segregates address spaces.\n"
                       + "Fix: use BPFJ.castUser/castKernel/castArena to cross boundaries.\n"
                       + "See: cookbook §Memory regions";
            detectOut.add(new Detection(at, "region.mixing", msg));
            return;
        }
        if (compilerPlugin == null) return;
        // (full message built in reportMixing)
    }

    private void reportMixing(AssignmentTree a, String varName, MemoryRegion prev, MemoryRegion rhs) {
        if (ctx.isSuppressed(a, "region.mixing")) return;
        var priorSite = lastRegionSite.get(varName);
        var priorLine = lineOf(priorSite);
        var priorLoc = priorSite == null
                ? "an earlier assignment"
                : (priorLine > 0 ? "line " + priorLine : "an earlier assignment");
        emitMixingError(a, varName, prev, rhs);
        if (compilerPlugin == null) return;
        compilerPlugin.logError(methodPath, a,
                "Cannot mix " + prev + " and " + rhs + " memory regions in '" + varName + "'.\n"
                        + "Why: BPF segregates address spaces; '" + varName + "' was previously "
                        + prev + " (" + priorLoc + ") and the right-hand side here is "
                        + rhs + " — joining them is rejected by the verifier.\n"
                        + "Fix: copy one side across the boundary first — "
                        + "BPFJ.castUser(...) / BPFJ.castKernel(...) / BPFJ.castArena(...), "
                        + "or use bpf_probe_read_user/_kernel into a stack buffer.\n"
                        + "See: cookbook §Memory regions");
    }

    /** Resolve the source line for {@code tree} via {@link CompilerPlugin}'s shared positions, or 0. */
    private long lineOf(Tree tree) {
        if (tree == null || compilerPlugin == null || compilerPlugin.trees == null) return 0;
        var cu = methodPath.root();
        var sp = compilerPlugin.trees.getSourcePositions();
        long pos = sp.getStartPosition(cu, tree);
        if (pos == javax.tools.Diagnostic.NOPOS) return 0;
        return cu.getLineMap().getLineNumber(pos);
    }

    private void warnUserDeref(ExpressionTree expr, String context) {
        if (ctx.isSuppressed(expr, "region.user-deref")) return;
        if (compilerPlugin == null) return;
        String varName = (expr instanceof IdentifierTree id) ? id.getName().toString() : "<expr>";
        compilerPlugin.logWarning(methodPath, expr,
                "Direct dereference of user-memory pointer '" + varName + "' in '" + context + "'.\n"
              + "Why: user-space pages may not be present; a direct deref can fault and is rejected "
              + "by the verifier. User memory must be copied across the boundary explicitly.\n"
              + "Fix: copy first via bpf_probe_read_user(&dst, sizeof(dst), " + varName + "), then use dst.\n"
              + "See: cookbook §Memory regions");
    }

    private void errorUserWrite(ExpressionTree expr, String context) {
        if (ctx.isSuppressed(expr, "region.user-write")) return;
        if (compilerPlugin == null) return;
        String varName = (expr instanceof IdentifierTree id) ? id.getName().toString() : "<expr>";
        compilerPlugin.logError(methodPath, expr,
                "Direct write to user-memory pointer '" + varName + "' in '" + context + "'.\n"
              + "Why: writing to user-space memory from BPF requires bpf_probe_write_user, which is "
              + "capability-gated (CAP_SYS_ADMIN) and dangerous; the verifier rejects naked writes "
              + "to a USER pointer.\n"
              + "Fix: stage the value in a stack local, then call bpf_probe_write_user(" + varName + ", &src, sizeof(src)) "
              + "explicitly — and only do this if you understand the security implications.\n"
              + "See: cookbook §Memory regions");
    }

    private static MethodSymbol getMethodSymbol(MethodInvocationTree call) {
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

    /**
     * Per-node annotation pass: re-evaluates expressions to populate {@link AnalysisContext#regionAt}
     * after the fixpoint converged.
     */
    private void annotateNode(FlowNode node, Map<String, MemoryRegion> env) {
        var inner = innerExpression(node.tree);
        if (inner != null) {
            evalExpression(inner, env);
        } else if (node.tree instanceof VariableTree v && v.getInitializer() != null) {
            evalExpression(v.getInitializer(), env);
        }
    }

    /**
     * Pull out the expression a flow node should evaluate, looking through statement
     * wrappers ({@link ReturnTree}, {@link ThrowTree}). Returns {@code null} if the
     * node has no inner expression to evaluate.
     */
    private static ExpressionTree innerExpression(Tree t) {
        return switch (t) {
            case ExpressionTree e -> e;
            case ReturnTree r -> r.getExpression();
            case ThrowTree th -> th.getExpression();
            case null -> null;
            default -> null;
        };
    }
}
