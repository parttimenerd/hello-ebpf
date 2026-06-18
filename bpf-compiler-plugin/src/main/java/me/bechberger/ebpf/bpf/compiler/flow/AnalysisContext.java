package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.Tree;

import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Shared per-method dataflow facts produced by analysis passes and consumed by the
 * {@code Translator} and downstream passes.
 *
 * <p>This is the "blackboard" of the unified type-system plan: each pass writes its slot;
 * later passes (or the Translator) read whichever slots they need. The slot mechanism is
 * extensible — new analyses just allocate a {@link Slot} and store their results without
 * modifying this class.
 *
 * <p>Standard slots are exposed as fields ({@link #regionAt}, {@link #nullAt},
 * {@link #packetGuarded}, {@link #programType}, {@link #suppressionsAt}). Custom slots use
 * {@link #put(Slot, Tree, Object)} / {@link #get(Slot, Tree)}.
 *
 * <p><b>Identity-keyed.</b> Tree references are stable through one compilation unit; passes
 * never mutate the AST. If a future pass introduces tree rewriting it must re-index ctx
 * (TODO documented in the unified plan §"Risks").
 */
public final class AnalysisContext {

    /** Region of every expression / declaration tree. Populated by {@code RegionAnalyzer}. */
    public final IdentityHashMap<Tree, MemoryRegion> regionAt = new IdentityHashMap<>();

    /** Nullability of every expression / declaration tree. Populated by {@code NullabilityAnalyzer}. */
    public final IdentityHashMap<Tree, NullabilityValue> nullAt = new IdentityHashMap<>();

    /** Packet derefs proven guarded by a {@code data_end} bounds-check. Populated by {@code BoundsCheckPass}. */
    public final Set<Tree> packetGuarded = Collections.newSetFromMap(new IdentityHashMap<>());

    /** Inferred BPF program type. Populated by {@code HelperContextPass}; defaults to {@code UNKNOWN}. */
    public ProgramTypeValue programType = ProgramTypeValue.UNKNOWN;

    /** Per-tree set of suppressed diagnostic categories. Populated by {@code SuppressionScan}. */
    public final IdentityHashMap<Tree, Set<String>> suppressionsAt = new IdentityHashMap<>();

    /** The CFG of the method body. Built once at the start of analysis; reused by all passes. */
    public ControlFlowGraph cfg;

    /** Custom slot storage. Keyed by {@link Slot} identity, then by {@link Tree} identity. */
    private final Map<Slot<?>, IdentityHashMap<Tree, Object>> slots = new HashMap<>();

    // ── queries ──────────────────────────────────────────────────────────

    public MemoryRegion regionOf(Tree t) {
        return regionAt.getOrDefault(t, MemoryRegion.UNKNOWN);
    }

    public NullabilityValue nullabilityOf(Tree t) {
        return nullAt.getOrDefault(t, NullabilityValue.UNKNOWN);
    }

    public boolean isSuppressed(Tree t, String category) {
        var set = suppressionsAt.get(t);
        return set != null && (set.contains(category) || set.contains("all"));
    }

    // ── extensible slots ─────────────────────────────────────────────────

    /**
     * Allocate a new slot for a custom analysis (e.g. capture analysis, constant prop).
     *
     * <pre>{@code
     *   private static final Slot<CapturePlan> CAPTURE = AnalysisContext.slot("capture");
     *   ...
     *   ctx.put(CAPTURE, lambdaTree, plan);
     *   var plan = ctx.get(CAPTURE, lambdaTree);
     * }</pre>
     */
    public static <V> Slot<V> slot(String name) {
        return new Slot<>(name);
    }

    @SuppressWarnings("unchecked")
    public <V> V get(Slot<V> slot, Tree tree) {
        var m = slots.get(slot);
        return m == null ? null : (V) m.get(tree);
    }

    public <V> void put(Slot<V> slot, Tree tree, V value) {
        slots.computeIfAbsent(slot, k -> new IdentityHashMap<>()).put(tree, value);
    }

    /** Type-safe slot identifier. Use {@link #slot(String)} to construct. */
    public static final class Slot<V> {
        public final String name;
        Slot(String name) { this.name = name; }
        @Override public String toString() { return "Slot(" + name + ")"; }
    }

    /**
     * Mirror of {@code me.bechberger.ebpf.annotations.bpf.ProgramType} kept here so the
     * {@code flow} package has zero dependencies on the annotations module. {@code HelperContextPass}
     * translates between the two enums.
     */
    public enum ProgramTypeValue {
        UNKNOWN,
        XDP, TC, KPROBE, KRETPROBE, FENTRY, FEXIT, KSYSCALL,
        UPROBE, URETPROBE, TRACEPOINT, RAW_TRACEPOINT,
        LSM, CGROUP_SKB, SOCKET, STRUCT_OPS, OTHER
    }
}
