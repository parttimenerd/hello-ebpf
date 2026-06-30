package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;

import javax.tools.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the Translator side-channel maps: {@code directArenaRefs} and
 * {@code callGraph}.  These are populated during translation of {@code @BPFFunction}
 * bodies and consumed by the forthcoming {@code ArenaAssociationPass} (Task B) to
 * determine which struct_ops entries need a per-prog arena-association injection.
 *
 * <p>Each test drives javac in-process (annotation processor +
 * {@code -Xplugin:BPFCompilerPlugin}) and then reads the side-channel via
 * {@link CompilerPlugin#LAST_PLUGIN}.
 */
public class ArenaAssociationPassTest {

    private static final String PKG = "arena_pass_test";

    /** Shared Java imports used by every fixture class. */
    private static String commonImports() {
        return "import me.bechberger.ebpf.annotations.*;\n"
                + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                + "import me.bechberger.ebpf.annotations.InArena;\n"
                + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                + "import me.bechberger.ebpf.bpf.BPFJ;\n"
                + "import me.bechberger.ebpf.bpf.map.BPFArena;\n"
                + "import me.bechberger.ebpf.type.Ptr;\n"
                + "import me.bechberger.ebpf.runtime.PtDefinitions;\n"
                + "import me.bechberger.ebpf.runtime.MmConstants;\n"
                + "import static me.bechberger.ebpf.bpf.BPFJ.bpfArenaAllocPages;\n";
    }

    /** Build a minimal {@code @BPF} abstract class source with the supplied body. */
    private static String bpfClassSource(String simpleName, String body) {
        return "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class " + simpleName + " extends BPFProgram {\n"
                + body
                + "\n}\n";
    }

    /** An in-memory JavaFileObject backed by a String source. */
    private static JavaFileObject sourceFile(String fqn, String src) {
        return new SimpleJavaFileObject(
                URI.create("string:///" + fqn.replace('.', '/') + ".java"),
                JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return src;
            }
        };
    }

    /**
     * Compile {@code sources} with both the BPF annotation processor and the
     * {@code BPFCompilerPlugin} compiler plugin running in-process.  After the
     * call, {@link CompilerPlugin#LAST_PLUGIN} holds the plugin instance that
     * processed the last {@code @BPF} implementation class.
     *
     * @return human-readable compiler output / diagnostics for failure messages
     */
    private static String compileWithPlugin(List<JavaFileObject> sources) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "No system Java compiler — run tests on a JDK, not a JRE.");
        }
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var fileManager = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8);

        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempDirectory("ebpf-arena-pass-test-");
        } catch (IOException e) {
            throw new RuntimeException("could not create temp dir", e);
        }

        // dumpC=false avoids writing stray .c files in the source tree.
        // We do NOT pass -proc:only because the CompilerPlugin runs during the
        // code-generation phase (AfterAnalyze), not the annotation-processing phase.
        List<String> options = Arrays.asList(
                "-classpath", System.getProperty("java.class.path"),
                "-Xplugin:BPFCompilerPlugin dumpC=false",
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var output = new StringWriter();
        var task = compiler.getTask(
                output, fileManager, diagnostics, options, null, sources);
        task.setProcessors(
                List.of(new me.bechberger.ebpf.bpf.processor.Processor()));

        try {
            task.call();
        } finally {
            try { fileManager.close(); } catch (IOException ignored) {}
            // Best-effort cleanup of the temp tree.
            try {
                java.nio.file.Files.walk(tmp)
                        .sorted(Comparator.reverseOrder())
                        .forEach(p -> {
                            try { java.nio.file.Files.deleteIfExists(p); }
                            catch (IOException ignored) {}
                        });
            } catch (IOException ignored) {}
        }

        // Collect diagnostics as a human-readable string for assertion messages.
        var sb = new StringBuilder(output.toString());
        for (var d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR
                    || d.getKind() == Diagnostic.Kind.WARNING) {
                sb.append(d.getKind()).append(": ")
                  .append(d.getMessage(Locale.ROOT)).append('\n');
            }
        }
        return sb.toString();
    }

    // ─── helper ──────────────────────────────────────────────────────────────

    private static CompilerPlugin compileAndGetPlugin(String simpleName, String body) {
        CompilerPlugin.LAST_PLUGIN.remove();
        var src = sourceFile(PKG + "." + simpleName,
                bpfClassSource(simpleName, body));
        var output = compileWithPlugin(List.of(src));
        var plugin = CompilerPlugin.LAST_PLUGIN.get();
        assertNotNull(plugin,
                "CompilerPlugin.LAST_PLUGIN must be set after compilation.\n"
                + "Compiler output:\n" + output);
        return plugin;
    }

    // ─── Test 1 ──────────────────────────────────────────────────────────────

    /**
     * A method that dereferences an {@code @InArena Ptr<Long>} field (via {@code p.val()},
     * i.e. {@code *p} in C) must produce a {@code directArenaRefs} entry mapping that
     * method to the arena-field name ({@code "a"}).
     */
    @Test
    public void directRefsCollectedForSingleMethod() {
        // @InArena field 'p' is initialised via bpfArenaAllocPages(a, ...).
        // Method 'f' dereferences it.  We expect directArenaRefs[f] = {"a"}.
        var plugin = compileAndGetPlugin("DirectRefsTest",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena a;\n"
                + "    @InArena Ptr<Long> p = bpfArenaAllocPages(a, null, 1, MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        p.val();\n"
                + "        return 0;\n"
                + "    }\n");

        var directRefs = plugin.getDirectArenaRefs();
        var fEntry = directRefs.entrySet().stream()
                .filter(e -> e.getKey().getSimpleName().contentEquals("f"))
                .findFirst();
        assertTrue(fEntry.isPresent(),
                "directArenaRefs must contain an entry for method 'f'.\n"
                + "Actual keys: "
                + directRefs.keySet().stream()
                        .map(s -> s.getSimpleName().toString())
                        .collect(Collectors.toList()));
        assertEquals(Set.of("a"), fEntry.get().getValue(),
                "directArenaRefs[f] must be {\"a\"}");
    }

    // ─── Test 2 ──────────────────────────────────────────────────────────────

    /**
     * When a {@code @BPFFunction} method {@code f} calls another {@code @BPFFunction}
     * method {@code g} in the same class, the {@code callGraph} entry for {@code f}
     * must contain {@code g}'s symbol.
     */
    @Test
    public void callEdgesCollectedAcrossMethods() {
        var plugin = compileAndGetPlugin("CallEdgesTest",
                "    @BPFFunction\n"
                + "    public void g() {}\n"
                + "\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        g();\n"
                + "        return 0;\n"
                + "    }\n");

        var graph = plugin.getCallGraph();
        var fEntry = graph.entrySet().stream()
                .filter(e -> e.getKey().getSimpleName().contentEquals("f"))
                .findFirst();
        assertTrue(fEntry.isPresent(),
                "callGraph must contain an entry for method 'f'.\n"
                + "Actual keys: "
                + graph.keySet().stream()
                        .map(s -> s.getSimpleName().toString())
                        .collect(Collectors.toList()));
        var callees = fEntry.get().getValue().stream()
                .map(s -> s.getSimpleName().toString())
                .collect(Collectors.toSet());
        assertTrue(callees.contains("g"),
                "callGraph[f] must contain 'g'.\nActual callees: " + callees);
    }

    // ─── Test: cross-class inheritance ───────────────────────────────────────

    /**
     * When a struct_ops entry handler in a child class calls a {@code @BPFFunction}
     * method that is INHERITED from a parent abstract {@code @BPF} class, the
     * call edge must be recorded.  Without this, transitive arena reachability
     * (Task B) would miss arena derefs that live in inherited helpers
     * (e.g. {@code UserspaceSchedulerBase.setBit} called from a concrete
     * scheduler's {@code sched_update_idle}).
     */
    @Test
    public void callEdgesCollectedAcrossInheritance() {
        CompilerPlugin.LAST_PLUGIN.remove();

        // Parent abstract @BPF class declares @BPFFunction void g().
        var parentSrc = sourceFile(PKG + ".InheritParent",
                "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class InheritParent extends BPFProgram {\n"
                + "    @BPFFunction\n"
                + "    public void g() {}\n"
                + "}\n");

        // Child @BPF class extends parent and calls inherited g() from a Kprobe.
        var childSrc = sourceFile(PKG + ".InheritChild",
                "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class InheritChild extends InheritParent {\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        g();\n"
                + "        return 0;\n"
                + "    }\n"
                + "}\n");

        var output = compileWithPlugin(List.of(parentSrc, childSrc));
        var plugin = CompilerPlugin.LAST_PLUGIN.get();
        assertNotNull(plugin,
                "CompilerPlugin.LAST_PLUGIN must be set after compilation.\n"
                + "Compiler output:\n" + output);

        var graph = plugin.getCallGraph();
        var fEntry = graph.entrySet().stream()
                .filter(e -> e.getKey().getSimpleName().contentEquals("f"))
                .findFirst();
        assertTrue(fEntry.isPresent(),
                "callGraph must contain an entry for method 'f' (child Kprobe).\n"
                + "Actual keys: "
                + graph.keySet().stream()
                        .map(s -> s.getSimpleName().toString())
                        .collect(Collectors.toList())
                + "\nCompiler output:\n" + output);
        var callees = fEntry.get().getValue().stream()
                .map(s -> s.getSimpleName().toString())
                .collect(Collectors.toSet());
        assertTrue(callees.contains("g"),
                "callGraph[f] must contain inherited 'g' from parent class.\n"
                + "Actual callees: " + callees);
    }

    // ─── Test 3 ──────────────────────────────────────────────────────────────

    /**
     * A method that declares an {@code @InArena} field but never dereferences it must
     * NOT produce a {@code directArenaRefs} entry (or must produce an empty set).
     */
    @Test
    public void noEntryWhenNoArenaDeref() {
        var plugin = compileAndGetPlugin("NoDerefTest",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena a;\n"
                + "    @InArena Ptr<Long> p = bpfArenaAllocPages(a, null, 1, MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        return 0;\n"
                + "    }\n");

        var directRefs = plugin.getDirectArenaRefs();
        var fEntry = directRefs.entrySet().stream()
                .filter(e -> e.getKey().getSimpleName().contentEquals("f"))
                .findFirst();
        assertTrue(fEntry.isEmpty() || fEntry.get().getValue().isEmpty(),
                "directArenaRefs must NOT have a non-empty entry for 'f' (no deref).\n"
                + "Actual: "
                + fEntry.map(e -> e.getValue()).orElse(Set.of()));
    }

    // ─── Test 4 ──────────────────────────────────────────────────────────────

    /**
     * A method that makes no calls to other {@code @BPFFunction} methods in the same
     * class must NOT produce a {@code callGraph} entry (or must produce an empty set).
     */
    @Test
    public void noCallGraphEntryForUnrelatedCalls() {
        // 'f' only returns 0 — no @BPFFunction peer calls, so callGraph[f] must be absent.
        var plugin = compileAndGetPlugin("NoCallEdgeTest",
                "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        return 0;\n"
                + "    }\n");

        var graph = plugin.getCallGraph();
        var fEntry = graph.entrySet().stream()
                .filter(e -> e.getKey().getSimpleName().contentEquals("f"))
                .findFirst();
        assertTrue(fEntry.isEmpty() || fEntry.get().getValue().isEmpty(),
                "callGraph must NOT have a non-empty entry for 'f' (no @BPFFunction peer calls).\n"
                + "Actual: "
                + fEntry.map(e -> e.getValue().stream()
                        .map(s -> s.getSimpleName().toString())
                        .collect(Collectors.toList()))
                        .orElse(List.of()));
    }

    // ─── Test C1: strict initializer guard ───────────────────────────────────

    /**
     * When an {@code @InArena Ptr<Long>} field is declared without an initializer (i.e. it
     * does not trace to a {@code bpfArenaAllocPages(arenaField, …)} call) and a method
     * dereferences it, the plugin must emit a compile-time error containing the field name
     * and the expected fix hint.
     */
    @Test
    public void uninitializedInArenaFieldDerefEmitsCompileError() {
        CompilerPlugin.LAST_PLUGIN.remove();
        // 'x' has no initializer — dereference in 'f' must produce a compile error.
        var src = sourceFile(PKG + ".UninitInArenaTest",
                "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class UninitInArenaTest extends BPFProgram {\n"
                + "    @BPFMapDefinition(maxEntries = 1) BPFArena myArena;\n"
                + "    @InArena me.bechberger.ebpf.type.Ptr<Long> x;\n"
                + "\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int f(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        x.val();\n"
                + "        return 0;\n"
                + "    }\n"
                + "}\n");
        var output = compileWithPlugin(List.of(src));
        assertTrue(output.contains("ERROR") || output.contains("error"),
                "Compilation of a class with uninitialized @InArena field deref must fail.\n"
                + "Actual output:\n" + output);
        assertTrue(output.contains("x"),
                "Error message must mention the offending field name 'x'.\n"
                + "Actual output:\n" + output);
        assertTrue(output.contains("bpfArenaAllocPages") || output.contains("arena"),
                "Error message must mention the fix hint (bpfArenaAllocPages / arena).\n"
                + "Actual output:\n" + output);
    }
}
