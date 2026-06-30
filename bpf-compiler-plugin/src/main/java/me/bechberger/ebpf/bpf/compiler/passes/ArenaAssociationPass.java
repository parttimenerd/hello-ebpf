package me.bechberger.ebpf.bpf.compiler.passes;

import com.sun.tools.javac.code.Symbol.MethodSymbol;
import me.bechberger.cast.CAST.Declarator.VerbatimFunctionDeclarator;
import me.bechberger.cast.CAST.Statement;
import me.bechberger.cast.CAST.Statement.CompoundStatement;
import me.bechberger.cast.CAST.Statement.FunctionDeclarationStatement;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin;
import me.bechberger.ebpf.bpf.compiler.CompilerPlugin.FuncDecl;

import java.util.*;

/**
 * Pass that auto-injects per-arena association helper calls into each
 * {@code struct_ops} entry handler that transitively dereferences a
 * {@code BPFArena}-backed {@code @InArena} pointer.
 *
 * <p>Background: the BPF verifier sets {@code prog->aux->arena} for a prog only
 * when its instruction stream contains a {@code BPF_PSEUDO_MAP_FD} ldimm64
 * referencing the arena map.  That ldimm64 survives clang only when {@code &arena}
 * is passed as an argument to a real kfunc/helper call.  Each {@code struct_ops}
 * entry is a <em>separate</em> prog, so every entry that uses arena-backed pointers
 * needs its own ldimm64.
 *
 * <p>This pass:
 * <ol>
 *   <li>Computes transitive arena reachability for each method via DFS over the
 *       {@link CompilerPlugin#callGraph}, accumulating
 *       {@link CompilerPlugin#directArenaRefs} along the way.</li>
 *   <li>For each {@code struct_ops} (or {@code struct_ops.s}) entry handler,
 *       records an injection plan — the sorted set of reachable arena names.</li>
 *   <li>Generates one {@code static __always_inline} helper per arena name:
 *       <pre>{@code
 *       static __always_inline void bpf_arena_associate_<N>(void) {
 *           static bool _verify_once;
 *           if (_verify_once) return;
 *           bpf_printk("arena=%p\n", (void *)(&<N>));
 *           _verify_once = true;
 *       }
 *       }</pre>
 *       Note: {@code bpf_arena_alloc_pages} cannot be used here because it is a sleepable
 *       kfunc that the verifier rejects in non-sleepable {@code struct_ops} handlers.
 *       {@code bpf_printk} is non-sleepable and forces clang to emit an {@code ldimm64}
 *       referencing the arena map, which is all the verifier needs to associate the prog.
 *       This matches the pattern used in the upstream scx library ({@code sdt_alloc.bpf.c
 *       scx_arena_subprog_init}).</li>
 *   <li>Prepends one {@code bpf_arena_associate_<N>();} call at the top of each
 *       struct_ops entry body, one call per reachable arena (sorted by name for
 *       deterministic output).</li>
 * </ol>
 *
 * <p>The pass is idempotent: if no struct_ops entry reaches any arena, nothing
 * is emitted and the input lists are returned unchanged.
 */
public class ArenaAssociationPass {

    /**
     * Result returned by {@link #apply}.
     *
     * @param updatedDecls the (possibly mutated) list of {@link FuncDecl} — the
     *                     struct_ops entries have association calls prepended to their bodies
     * @param helperDecls  zero or more {@code static __always_inline} helper
     *                     {@link FunctionDeclarationStatement} objects to emit at file scope
     *                     before the entry functions
     */
    public record Result(
            List<FuncDecl> updatedDecls,
            List<FunctionDeclarationStatement> helperDecls) {}

    /**
     * Applies the pass.
     *
     * @param plugin        the {@link CompilerPlugin} instance that owns the side-channel maps
     * @param methodSymbols parallel list of {@link MethodSymbol} objects — {@code methodSymbols.get(i)}
     *                      is the Java method that produced {@code decls.get(i)}
     * @param decls         the list of translated {@link FuncDecl} objects (entry functions)
     * @return a {@link Result} containing the (possibly updated) decl list and any new helpers
     */
    public Result apply(
            CompilerPlugin plugin,
            List<MethodSymbol> methodSymbols,
            List<FuncDecl> decls) {

        if (methodSymbols.size() != decls.size()) {
            throw new IllegalArgumentException(
                    "methodSymbols and decls must have the same size; got "
                    + methodSymbols.size() + " vs " + decls.size());
        }

        // Step 1: compute transitive arena reachability for every method.
        Map<MethodSymbol, Set<String>> transitiveArenas = new HashMap<>();
        for (MethodSymbol m : methodSymbols) {
            Set<String> reachable = computeTransitiveArenas(m, plugin, new HashSet<>());
            transitiveArenas.put(m, reachable);
        }

        // Step 2: identify struct_ops entries and their injection plans.
        // injectionPlan: index in decls -> sorted list of arena names to inject
        Map<Integer, List<String>> injectionPlan = new LinkedHashMap<>();
        for (int i = 0; i < methodSymbols.size(); i++) {
            MethodSymbol m = methodSymbols.get(i);
            BPFFunction bpfFn = plugin.getEffectiveBPFFunction(m);
            if (bpfFn == null) continue;
            // Identify struct_ops entries two ways:
            //   (a) section() starts with "struct_ops/" or "struct_ops.s/" (explicit SEC annotation)
            //   (b) headerTemplate contains "BPF_STRUCT_OPS(" or "BPF_STRUCT_OPS_SLEEPABLE("
            //       — this covers Scheduler interface methods that use BPF_STRUCT_OPS macro but
            //       leave section() empty (the macro itself emits the SEC attribute in C).
            String section = bpfFn.section();
            String headerTpl = bpfFn.headerTemplate();
            boolean isStructOpsEntry =
                    section.startsWith("struct_ops/") || section.startsWith("struct_ops.s/")
                    || headerTpl.contains("BPF_STRUCT_OPS(") || headerTpl.contains("BPF_STRUCT_OPS_SLEEPABLE(");
            if (!isStructOpsEntry) continue;
            Set<String> arenas = transitiveArenas.get(m);
            if (arenas == null || arenas.isEmpty()) continue;
            var sorted = new ArrayList<>(arenas);
            Collections.sort(sorted);
            injectionPlan.put(i, sorted);
        }

        if (injectionPlan.isEmpty()) {
            // Nothing to do.
            return new Result(decls, List.of());
        }

        // Step 3: collect all distinct arena names appearing in any injection plan.
        Set<String> allArenasOrdered = new LinkedHashSet<>();
        for (List<String> names : injectionPlan.values()) {
            allArenasOrdered.addAll(names);
        }
        List<String> sortedAllArenas = new ArrayList<>(allArenasOrdered);
        Collections.sort(sortedAllArenas);

        // Step 4: generate one helper per arena.
        List<FunctionDeclarationStatement> helpers = new ArrayList<>();
        for (String arenaName : sortedAllArenas) {
            helpers.add(buildHelperFunction(arenaName));
        }

        // Step 5: prepend association calls to each struct_ops entry body.
        var updatedDecls = new ArrayList<>(decls);
        for (Map.Entry<Integer, List<String>> entry : injectionPlan.entrySet()) {
            int idx = entry.getKey();
            List<String> arenaNames = entry.getValue();
            FuncDecl fd = updatedDecls.get(idx);

            var existingStatements = new ArrayList<>(fd.decl().body().statements());
            var injected = new ArrayList<Statement>();
            for (String arenaName : arenaNames) {
                injected.add(Statement.verbatim("bpf_arena_associate_" + arenaName + "();"));
            }
            injected.addAll(existingStatements);

            var newBody = new CompoundStatement(injected);
            var newDecl = new FunctionDeclarationStatement(
                    fd.decl().declarator(), newBody, fd.decl().annotations());
            updatedDecls.set(idx, new FuncDecl(newDecl, fd.addDefine()));
        }

        return new Result(List.copyOf(updatedDecls), List.copyOf(helpers));
    }

    /**
     * Generates the C body for the per-arena association helper.
     *
     * <p>Uses {@link VerbatimFunctionDeclarator} so the full
     * {@code static __always_inline void bpf_arena_associate_<N>(void)} header
     * is emitted verbatim, which avoids needing to construct a full
     * FunctionDeclarator with return types, modifiers, etc.
     *
     * <p>Uses {@code bpf_printk("arena=%p\\n", &<N>)} (not {@code bpf_arena_alloc_pages})
     * because {@code bpf_arena_alloc_pages} is a sleepable kfunc rejected in non-sleepable
     * {@code struct_ops} entry handlers. {@code bpf_printk} is non-sleepable and forces
     * clang to emit a {@code ldimm64} referencing {@code &arena}, which is all the BPF
     * verifier needs to associate the prog. Pattern from upstream scx ({@code sdt_alloc.bpf.c}).
     */
    private FunctionDeclarationStatement buildHelperFunction(String arenaName) {
        var header = new VerbatimFunctionDeclarator(
                "static __always_inline void bpf_arena_associate_" + arenaName + "(void)");

        List<Statement> bodyStatements = new ArrayList<>();
        bodyStatements.add(Statement.verbatim("static bool _verify_once;"));
        bodyStatements.add(Statement.verbatim("if (_verify_once) return;"));
        // bpf_printk forces clang to emit an ldimm64 referencing &arena so the BPF verifier
        // sets prog->aux->arena for this program.  bpf_arena_alloc_pages cannot be used here
        // because it is a sleepable kfunc, which the verifier rejects in non-sleepable
        // struct_ops entry handlers.  The "%p" format string is needed to reference the arena
        // pointer value; clang optimises away arguments that are never formatted.
        // Pattern from scx upstream (sdt_alloc.bpf.c scx_arena_subprog_init).
        bodyStatements.add(Statement.verbatim(
                "bpf_printk(\"arena=%p\\n\", (void *)(&" + arenaName + "));"));
        bodyStatements.add(Statement.verbatim("_verify_once = true;"));

        return new FunctionDeclarationStatement(header, new CompoundStatement(bodyStatements));
    }

    /**
     * DFS over the call graph to compute the transitive set of arena names
     * reachable from {@code method}.
     *
     * <p>Visiting is guarded by {@code visited} to handle mutual recursion.
     */
    private Set<String> computeTransitiveArenas(
            MethodSymbol method,
            CompilerPlugin plugin,
            Set<MethodSymbol> visited) {
        if (!visited.add(method)) {
            return Set.of();
        }
        Set<String> result = new HashSet<>();
        // Direct arena derefs from this method.
        Set<String> direct = plugin.getDirectArenaRefs().get(method);
        if (direct != null) {
            result.addAll(direct);
        }
        // Transitive: recurse into callees.
        Set<MethodSymbol> callees = plugin.getCallGraph().get(method);
        if (callees != null) {
            for (MethodSymbol callee : callees) {
                result.addAll(computeTransitiveArenas(callee, plugin, visited));
            }
        }
        return result;
    }
}
