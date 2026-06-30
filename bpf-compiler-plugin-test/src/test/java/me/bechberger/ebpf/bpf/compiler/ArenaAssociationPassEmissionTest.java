package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;

import javax.tools.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Emission tests for {@code ArenaAssociationPass}: verifies that the pass
 * correctly injects {@code bpf_arena_associate_<N>()} calls into {@code struct_ops}
 * entry handler bodies and emits the corresponding {@code static __always_inline}
 * helper functions at file scope.
 *
 * <p>All tests compile Java source in-process via javac, running both the
 * annotation processor and the {@code BPFCompilerPlugin}.  After compilation,
 * the generated C is retrieved from {@link CompilerPlugin#getLastGeneratedCode()}.
 *
 * <p>This file extends the coverage of {@link ArenaAssociationPassTest} (which
 * tests the Task A side-channel maps).  The two test classes are run together
 * as {@code ArenaAssociationPass*}.
 */
public class ArenaAssociationPassEmissionTest {

    private static final String PKG = "arena_pass_emission_test";

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

    private static String bpfClassSource(String simpleName, String body) {
        return "package " + PKG + ";\n"
                + commonImports()
                + "@BPF(license = \"GPL\")\n"
                + "public abstract class " + simpleName + " extends BPFProgram {\n"
                + body
                + "\n}\n";
    }

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
     * Compile a single-class BPF source and return the plugin instance.
     * LAST_PLUGIN is cleared before compilation so each test gets a fresh reference.
     * The generated C is available via {@link CompilerPlugin#getLastGeneratedCode()}.
     */
    private static CompilerPlugin compileAndGetPlugin(String simpleName, String body) {
        CompilerPlugin.LAST_PLUGIN.remove();
        var src = sourceFile(PKG + "." + simpleName,
                bpfClassSource(simpleName, body));

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
            tmp = java.nio.file.Files.createTempDirectory("ebpf-arena-emit-test-");
        } catch (IOException e) {
            throw new RuntimeException("could not create temp dir", e);
        }

        List<String> options = Arrays.asList(
                "-classpath", System.getProperty("java.class.path"),
                "-Xplugin:BPFCompilerPlugin dumpC=false",
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var output = new StringWriter();
        var task = compiler.getTask(
                output, fileManager, diagnostics, options, null, List.of(src));
        task.setProcessors(
                List.of(new me.bechberger.ebpf.bpf.processor.Processor()));

        try {
            task.call();
        } finally {
            try { fileManager.close(); } catch (IOException ignored) {}
            try {
                java.nio.file.Files.walk(tmp)
                        .sorted(Comparator.reverseOrder())
                        .forEach(p -> {
                            try { java.nio.file.Files.deleteIfExists(p); }
                            catch (IOException ignored) {}
                        });
            } catch (IOException ignored) {}
        }

        var sb = new StringBuilder(output.toString());
        for (var d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR
                    || d.getKind() == Diagnostic.Kind.WARNING) {
                sb.append(d.getKind()).append(": ")
                  .append(d.getMessage(Locale.ROOT)).append('\n');
            }
        }
        String compilerOutput = sb.toString();

        var plugin = CompilerPlugin.LAST_PLUGIN.get();
        assertNotNull(plugin,
                "CompilerPlugin.LAST_PLUGIN must be set after compilation.\n"
                + "Compiler output:\n" + compilerOutput);
        return plugin;
    }

    // ─── Test 1 ──────────────────────────────────────────────────────────────

    /**
     * A {@code struct_ops} entry handler that dereferences an {@code @InArena} field
     * backed by {@code arena1} must receive a {@code bpf_arena_associate_arena1();}
     * injection at the top of its body, and a corresponding helper function must be
     * emitted at file scope.
     */
    @Test
    public void injectsAtStructOpsEntries() {
        var plugin = compileAndGetPlugin("StructOpsArenaInject",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena arena1;\n"
                + "    @InArena Ptr<Long> p = bpfArenaAllocPages(arena1, null, 1,"
                + " MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @BPFFunction(section = \"struct_ops/some_handler\")\n"
                + "    public int handler(int x) {\n"
                + "        p.val();\n"
                + "        return 0;\n"
                + "    }\n");

        String code = plugin.getLastGeneratedCode();

        // The helper function must exist at file scope.
        assertTrue(code.contains("static __always_inline void bpf_arena_associate_arena1(void)"),
                "Expected 'static __always_inline void bpf_arena_associate_arena1(void)' "
                + "in generated C:\n" + code);
        assertTrue(code.contains("bpf_arena_alloc_pages(&arena1, NULL, 0, NUMA_NO_NODE, 0)"),
                "Expected 'bpf_arena_alloc_pages(&arena1, ...)' inside helper in generated C:\n" + code);

        // The call must be injected into the handler body.
        assertTrue(code.contains("bpf_arena_associate_arena1();"),
                "Expected 'bpf_arena_associate_arena1();' call in handler body in generated C:\n" + code);

        // The helper must appear before the call site in the output.
        int helperPos = code.indexOf("static __always_inline void bpf_arena_associate_arena1(void)");
        int callPos   = code.indexOf("bpf_arena_associate_arena1();");
        assertTrue(helperPos >= 0 && callPos >= 0 && helperPos < callPos,
                "Helper definition must precede the call site in generated C:\n" + code);
    }

    // ─── Test 2 ──────────────────────────────────────────────────────────────

    /**
     * A {@code @Kprobe} method (not a {@code struct_ops} entry) that dereferences an
     * arena must NOT receive any injection — the helper is only emitted when at least
     * one struct_ops entry reaches the arena.
     */
    @Test
    public void doesNotInjectIntoNonStructOps() {
        var plugin = compileAndGetPlugin("NonStructOpsNoInject",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena arena1;\n"
                + "    @InArena Ptr<Long> p = bpfArenaAllocPages(arena1, null, 1,"
                + " MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @Kprobe(\"do_sys_openat2\")\n"
                + "    public int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {\n"
                + "        p.val();\n"
                + "        return 0;\n"
                + "    }\n");

        String code = plugin.getLastGeneratedCode();

        assertFalse(code.contains("bpf_arena_associate_"),
                "No 'bpf_arena_associate_' call/helper should appear for a non-struct_ops "
                + "handler:\n" + code);
    }

    // ─── Test 3 ──────────────────────────────────────────────────────────────

    /**
     * A {@code struct_ops} entry that calls a {@code @BPFFunction} subprogram which in
     * turn dereferences the arena must receive the injection at the entry's top.
     * Subprograms share {@code prog->aux->arena} with the entry and do not need their
     * own ldimm64 — only the entry needs the association call.
     */
    @Test
    public void transitivelyInjectsThroughSubprogramCall() {
        var plugin = compileAndGetPlugin("TransitiveArenaInject",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena arena1;\n"
                + "    @InArena Ptr<Long> p = bpfArenaAllocPages(arena1, null, 1,"
                + " MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @BPFFunction\n"
                + "    public int helper() {\n"
                + "        p.val();\n"
                + "        return 0;\n"
                + "    }\n"
                + "\n"
                + "    @BPFFunction(section = \"struct_ops/entry_point\")\n"
                + "    public int entryPoint(int x) {\n"
                + "        return helper();\n"
                + "    }\n");

        String code = plugin.getLastGeneratedCode();

        // Injection must appear in the output (from the entry point).
        assertTrue(code.contains("bpf_arena_associate_arena1();"),
                "Expected transitive injection 'bpf_arena_associate_arena1();' in generated C:\n" + code);

        // The helper function must be emitted.
        assertTrue(code.contains("static __always_inline void bpf_arena_associate_arena1(void)"),
                "Expected helper declaration in generated C:\n" + code);
    }

    // ─── Test 4 ──────────────────────────────────────────────────────────────

    /**
     * A {@code struct_ops} entry that does not transitively reach any arena must
     * receive no injection and no helper must be emitted.
     */
    @Test
    public void doesNotInjectWhenNoArenaReached() {
        var plugin = compileAndGetPlugin("StructOpsNoArena",
                "    @BPFFunction(section = \"struct_ops/no_arena_handler\")\n"
                + "    public int handler(int x) {\n"
                + "        return x + 1;\n"
                + "    }\n");

        String code = plugin.getLastGeneratedCode();

        assertFalse(code.contains("bpf_arena_associate_"),
                "No 'bpf_arena_associate_' should appear when no arena is reached:\n" + code);
    }

    // ─── Test 5 ──────────────────────────────────────────────────────────────

    /**
     * A {@code struct_ops} entry that reaches two distinct arenas must receive two
     * association calls injected (one per arena, sorted by name).
     */
    @Test
    public void multipleArenasInOneHandler() {
        var plugin = compileAndGetPlugin("MultiArenaInject",
                "    @BPFMapDefinition(maxEntries = 1) BPFArena arenaA;\n"
                + "    @BPFMapDefinition(maxEntries = 1) BPFArena arenaB;\n"
                + "    @InArena Ptr<Long> pA = bpfArenaAllocPages(arenaA, null, 1,"
                + " MmConstants.NUMA_NO_NODE, 0);\n"
                + "    @InArena Ptr<Long> pB = bpfArenaAllocPages(arenaB, null, 1,"
                + " MmConstants.NUMA_NO_NODE, 0);\n"
                + "\n"
                + "    @BPFFunction(section = \"struct_ops/multi_handler\")\n"
                + "    public int handler(int x) {\n"
                + "        pA.val();\n"
                + "        pB.val();\n"
                + "        return 0;\n"
                + "    }\n");

        String code = plugin.getLastGeneratedCode();

        assertTrue(code.contains("bpf_arena_associate_arenaA();"),
                "Expected 'bpf_arena_associate_arenaA();' in generated C:\n" + code);
        assertTrue(code.contains("bpf_arena_associate_arenaB();"),
                "Expected 'bpf_arena_associate_arenaB();' in generated C:\n" + code);
        assertTrue(code.contains("static __always_inline void bpf_arena_associate_arenaA(void)"),
                "Expected arenaA helper declaration in generated C:\n" + code);
        assertTrue(code.contains("static __always_inline void bpf_arena_associate_arenaB(void)"),
                "Expected arenaB helper declaration in generated C:\n" + code);

        // Both helpers must appear before their call sites.
        int helperAPos = code.indexOf("static __always_inline void bpf_arena_associate_arenaA(void)");
        int helperBPos = code.indexOf("static __always_inline void bpf_arena_associate_arenaB(void)");
        int callAPos   = code.indexOf("bpf_arena_associate_arenaA();");
        int callBPos   = code.indexOf("bpf_arena_associate_arenaB();");
        assertTrue(helperAPos >= 0 && callAPos >= 0 && helperAPos < callAPos,
                "Helper arenaA must precede its call site:\n" + code);
        assertTrue(helperBPos >= 0 && callBPos >= 0 && helperBPos < callBPos,
                "Helper arenaB must precede its call site:\n" + code);
    }
}
