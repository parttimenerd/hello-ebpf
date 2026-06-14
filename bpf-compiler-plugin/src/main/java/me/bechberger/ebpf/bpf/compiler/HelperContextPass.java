package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.*;
import com.sun.source.util.TreeScanner;
import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.ProgramType;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.TypedTreePath;
import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Helper-context inference pass.
 *
 * <p>For each {@code @BPFFunction} entry method, infers the BPF program type from
 * its section string ({@code "xdp"}, {@code "kprobe/..."}, {@code "tp/..."}, etc.)
 * and walks the method body looking for {@code @BuiltinBPFFunction} calls. If the
 * called helper is a kernel helper known to be illegal in the entry method's
 * program type, a {@code WARNING} is emitted at the Java call site.
 *
 * <p><b>MVP scope.</b> Only direct calls in the entry method body are checked
 * (no transitive call-graph walk). The compatibility table is curated for a
 * small set of commonly-misused helpers; methods not in the table are not
 * checked. The pass emits warnings, not errors, so a heuristic miss never
 * breaks a build — promotion to error can come once the table is exhaustive.
 *
 * <p>Helper compatibility data is taken from the kernel's
 * {@code BPF_PROG_TYPE_*}/{@code BPF_FUNC_*} compatibility matrix; entries
 * here mirror that matrix but only for the helpers we explicitly track.
 */
public class HelperContextPass {

    private final CompilerPlugin compilerPlugin;
    private final TypedTreePath<MethodTree> methodPath;
    private final AnalysisContext ctx;

    /**
     * Curated kernel-helper → allowed-program-types table.
     *
     * <p>Keyed by the {@code bpf_*} symbol name extracted from
     * {@link BuiltinBPFFunction#value()}. Helpers absent from this map are
     * treated as program-type-agnostic (no check).
     */
    private static final Map<String, Set<ProgramType>> HELPER_COMPAT = Map.ofEntries(
            // Process-context helpers — illegal in XDP, TC, cgroup_skb (no current task).
            Map.entry("bpf_get_current_task", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL,
                    ProgramType.LSM, ProgramType.STRUCT_OPS)),
            Map.entry("bpf_get_current_task_btf", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL,
                    ProgramType.LSM, ProgramType.STRUCT_OPS)),
            Map.entry("bpf_get_current_pid_tgid", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL,
                    ProgramType.LSM, ProgramType.STRUCT_OPS, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_get_current_uid_gid", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL,
                    ProgramType.LSM, ProgramType.STRUCT_OPS, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_get_current_comm", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL,
                    ProgramType.LSM, ProgramType.STRUCT_OPS, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_send_signal", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL)),
            Map.entry("bpf_send_signal_thread", EnumSet.of(
                    ProgramType.KPROBE, ProgramType.KRETPROBE, ProgramType.FENTRY, ProgramType.FEXIT,
                    ProgramType.TRACEPOINT, ProgramType.RAW_TRACEPOINT, ProgramType.KSYSCALL)),

            // XDP-only adjustments — illegal everywhere else.
            Map.entry("bpf_xdp_adjust_head", EnumSet.of(ProgramType.XDP)),
            Map.entry("bpf_xdp_adjust_tail", EnumSet.of(ProgramType.XDP)),
            Map.entry("bpf_xdp_adjust_meta", EnumSet.of(ProgramType.XDP)),
            Map.entry("bpf_xdp_load_bytes", EnumSet.of(ProgramType.XDP)),
            Map.entry("bpf_xdp_store_bytes", EnumSet.of(ProgramType.XDP)),

            // sk_buff (TC / cgroup_skb) helpers — illegal in XDP / kprobe / etc.
            Map.entry("bpf_skb_load_bytes", EnumSet.of(
                    ProgramType.TC, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_skb_store_bytes", EnumSet.of(
                    ProgramType.TC, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_skb_pull_data", EnumSet.of(
                    ProgramType.TC, ProgramType.CGROUP_SKB)),
            Map.entry("bpf_skb_change_proto", EnumSet.of(ProgramType.TC)),
            Map.entry("bpf_skb_change_type", EnumSet.of(ProgramType.TC)),
            Map.entry("bpf_skb_change_tail", EnumSet.of(ProgramType.TC)),
            Map.entry("bpf_skb_change_head", EnumSet.of(ProgramType.TC)),
            Map.entry("bpf_l3_csum_replace", EnumSet.of(ProgramType.TC)),
            Map.entry("bpf_l4_csum_replace", EnumSet.of(ProgramType.TC))
    );

    /**
     * Closest-allowed helper alternative per (helper, program-type-where-rejected) pair.
     * Plan §"Stage 10 cross-pass enrichment" — turns "Helper X is not allowed in P" into
     * "Helper X is not allowed in P; use Y instead" when a sensible sibling exists.
     */
    private static final Map<String, Map<ProgramType, String>> ALTERNATIVES = Map.ofEntries(
            Map.entry("bpf_skb_load_bytes", Map.of(
                    ProgramType.XDP, "bpf_xdp_load_bytes")),
            Map.entry("bpf_skb_store_bytes", Map.of(
                    ProgramType.XDP, "bpf_xdp_store_bytes")),
            Map.entry("bpf_xdp_load_bytes", Map.of(
                    ProgramType.TC, "bpf_skb_load_bytes",
                    ProgramType.CGROUP_SKB, "bpf_skb_load_bytes")),
            Map.entry("bpf_xdp_store_bytes", Map.of(
                    ProgramType.TC, "bpf_skb_store_bytes",
                    ProgramType.CGROUP_SKB, "bpf_skb_store_bytes")),
            Map.entry("bpf_xdp_adjust_head", Map.of(
                    ProgramType.TC, "bpf_skb_change_head")),
            Map.entry("bpf_xdp_adjust_tail", Map.of(
                    ProgramType.TC, "bpf_skb_change_tail"))
    );

    public HelperContextPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath) {
        this(compilerPlugin, methodPath, new AnalysisContext());
    }

    public HelperContextPass(CompilerPlugin compilerPlugin, TypedTreePath<MethodTree> methodPath,
                             AnalysisContext ctx) {
        this.compilerPlugin = compilerPlugin;
        this.methodPath = methodPath;
        this.ctx = ctx;
    }

    public void analyze() {
        var method = methodPath.leaf();
        var body = method.getBody();
        if (body == null) return;

        var element = compilerPlugin.trees.getElement(methodPath.path());
        if (!(element instanceof MethodSymbol entrySym)) return;

        var bpfFunc = compilerPlugin.getEffectiveBPFFunction(entrySym);
        if (bpfFunc == null) return;
        var programType = ProgramType.fromSection(bpfFunc.section());
        if (programType == ProgramType.UNKNOWN) return;

        // Mirror into the analysis context so other passes can query without re-deriving.
        ctx.programType = mapProgramType(programType);

        new TreeScanner<Void, Void>() {
            @Override
            public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
                checkCall(node, programType);
                return super.visitMethodInvocation(node, p);
            }
        }.scan(body, null);
    }

    private static AnalysisContext.ProgramTypeValue mapProgramType(ProgramType pt) {
        try {
            return AnalysisContext.ProgramTypeValue.valueOf(pt.name());
        } catch (IllegalArgumentException e) {
            return AnalysisContext.ProgramTypeValue.OTHER;
        }
    }

    private void checkCall(MethodInvocationTree call, ProgramType programType) {
        var sym = methodSymbol(call);
        if (sym == null) return;
        var template = compilerPlugin.getAnnotationOfMethodOrSuper(sym, BuiltinBPFFunction.class);
        if (template == null) return;

        var helper = extractHelperName(template.value());
        if (helper == null) {
            // Default template "$name($args)" → helper symbol is the Java method name.
            var name = sym.getSimpleName().toString();
            if (name.startsWith("bpf_")) helper = name;
        }
        if (helper == null) return;

        var allowed = HELPER_COMPAT.get(helper);
        if (allowed == null) return; // helper not tracked — skip
        if (allowed.contains(programType)) return;

        var alt = ALTERNATIVES.getOrDefault(helper, Map.of()).get(programType);
        var fixLine = alt != null
                ? "Fix: use '" + alt + "' instead — it's the closest helper that works on "
                        + programType + " context. Otherwise move this call into a section that "
                        + "allows it (allowed in: " + allowed + ").\n"
                : "Fix: either move this call into a program section that allows it (allowed in: "
                        + allowed + "), or use a context-equivalent helper (see cookbook §Helpers).\n";

        compilerPlugin.logWarning(methodPath, call,
                "Helper '" + helper + "' is not allowed in " + programType + " programs.\n"
              + "Why: BPF helpers are gated by program type; the verifier checks the program's "
              + "section against the helper's allowed-context list and rejects mismatches at "
              + "load time.\n"
              + fixLine
              + "See: cookbook §Helpers");
    }

    /**
     * Extract the leading {@code bpf_*} symbol from a {@link BuiltinBPFFunction#value()}
     * template (e.g. {@code "bpf_get_current_task()"} → {@code "bpf_get_current_task"}).
     * Returns {@code null} if the template doesn't start with a {@code bpf_} call.
     */
    static String extractHelperName(String template) {
        if (template == null || template.isEmpty()) return null;
        var s = template.trim();
        // Strip leading C-style casts like "(long) " or doubled "(int) (long) " before looking
        // for the call paren. Loop because some templates stack casts (e.g. "(int) (long) bpf_x()").
        while (s.startsWith("(")) {
            int close = s.indexOf(')');
            if (close < 0) return null;
            s = s.substring(close + 1).trim();
        }
        int paren = s.indexOf('(');
        if (paren <= 0) return null;
        var head = s.substring(0, paren).trim();
        // Drop any space-separated prefix (defensive).
        int lastSpace = head.lastIndexOf(' ');
        if (lastSpace >= 0) head = head.substring(lastSpace + 1);
        return head.startsWith("bpf_") ? head : null;
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
