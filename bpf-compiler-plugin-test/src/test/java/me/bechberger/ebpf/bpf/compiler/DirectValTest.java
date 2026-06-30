package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.AllowDirectVal;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
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
 * TDD unit tests for the {@code Ptr.directVal()} structural check and C-generation
 * behaviour.
 *
 * <p>Expected green/red split <em>after Task 4 lands</em> (TDD red phase):
 * <ul>
 *   <li>GREEN (no downstream task needed): tests 1, 6, 7 — C-generation assertions
 *       that hold with the current {@code @BuiltinBPFFunction("(*($this))")} stub.</li>
 *   <li>RED (requires Task 7): test 2 — asserts a structural-check error that Task 7
 *       will emit when {@code directVal()} is not followed by a field access.</li>
 *   <li>Expected GREEN (trivially, because no structural check exists yet) then RED
 *       momentarily during Task 7 partial implementation, then GREEN again once
 *       override resolution is also wired: tests 3, 4, 5 — assert that valid override
 *       annotations suppress the structural-check error.</li>
 * </ul>
 *
 * <p>All 7 tests must be GREEN in the fully-implemented state (after Tasks 5, 6, 7).
 */
class DirectValTest {

    // ─── helpers: C-generation ────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    static String codeOf(Class<?> cls) {
        return BPFProgram.getCode((Class<? extends BPFProgram>) cls);
    }

    static String stripped(String code) {
        return code.lines()
                .filter(l -> !l.trim().startsWith("#line "))
                .map(l -> l.replace("__always_inline ", ""))
                .collect(Collectors.joining("\n"));
    }

    // ─── helpers: in-memory compile with diagnostic collection ────────────────

    private static final String PKG = "directval_test";

    private static String commonImports() {
        return "import me.bechberger.ebpf.annotations.*;\n"
                + "import me.bechberger.ebpf.annotations.bpf.*;\n"
                + "import me.bechberger.ebpf.bpf.BPFProgram;\n"
                + "import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;\n"
                + "import me.bechberger.ebpf.type.Ptr;\n";
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
     * A simple diagnostic record for readable assertions.
     *
     * @param kind    e.g. "ERROR", "WARNING"
     * @param message the diagnostic message
     */
    record DiagEntry(String kind, String message) {}

    /**
     * Compile {@code source} in-memory (annotation processor + compiler plugin),
     * collect all diagnostics, and return them as {@link DiagEntry} records.
     * Does NOT throw on compilation failure — the caller decides what to assert.
     */
    private static List<DiagEntry> compileAndCollectDiagnostics(String simpleName, String src) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "No system Java compiler — run tests on a JDK, not a JRE.");
        }
        var diagnosticCollector = new DiagnosticCollector<JavaFileObject>();
        var fileManager = compiler.getStandardFileManager(
                diagnosticCollector, Locale.ROOT, StandardCharsets.UTF_8);

        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempDirectory("ebpf-directval-test-");
        } catch (IOException e) {
            throw new RuntimeException("could not create temp dir", e);
        }

        List<String> options = Arrays.asList(
                "-classpath", System.getProperty("java.class.path"),
                "-Xplugin:BPFCompilerPlugin dumpC=false",
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var fqn = PKG + "." + simpleName;
        var jfo = sourceFile(fqn, src);

        var output = new StringWriter();
        var task = compiler.getTask(output, fileManager, diagnosticCollector, options, null,
                List.of(jfo));
        task.setProcessors(List.of(new me.bechberger.ebpf.bpf.processor.Processor()));

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

        return diagnosticCollector.getDiagnostics().stream()
                .map(d -> new DiagEntry(d.getKind().name(),
                        d.getMessage(Locale.ROOT)))
                .collect(Collectors.toList());
    }

    // ─── Test 1: directVal() before MemberSelect emits direct field access ────
    //
    // GREEN in Task 4 state:
    //   p.directVal() is @BuiltinBPFFunction("(*($this))") → emits (*(p)) in C.
    //   stripPtrVal() only matches "val", so the (*p) is NOT pierced for CO-RE lifting.
    //   The subsequent MemberSelect .pid produces (*p).pid, which clang lowers to p->pid.
    //   BPF_CORE_READ must NOT appear.
    //
    // Must still be GREEN after Tasks 5-7.

    @BPF(license = "GPL")
    public static abstract class DirectValMemberSelectFixture extends BPFProgram {

        @BPFFunction
        public int readPid(Ptr<task_struct> p) {
            return p.directVal().pid;
        }
    }

    @Test
    void directValBeforeMemberSelectEmitsDirectAccess() {
        String c = stripped(codeOf(DirectValMemberSelectFixture.class));
        // The expression p->pid (or the equivalent (*p).pid) must appear.
        assertTrue(c.contains("p->pid") || c.contains("(*p)") || c.contains("(*(p))"),
                "Expected direct field access for p.directVal().pid; got:\n" + c);
        // BPF_CORE_READ must NOT appear (directVal is not stripped by stripPtrVal).
        assertFalse(c.contains("BPF_CORE_READ(p, pid)"),
                "directVal() must suppress BPF_CORE_READ lifting; got:\n" + c);
    }

    // ─── Test 2: directVal() without MemberSelect must be a compile error ─────
    //
    // RED in Task 4 state (no structural check yet):
    //   The structural check (Task 7) is not yet implemented, so no plugin error is
    //   raised. This assertion will FAIL — that is the correct TDD-red state.
    //
    // Must be GREEN after Task 7 adds the structural check.

    @Test
    void directValWithoutMemberSelectErrors() {
        // Fixture: assign p.directVal() to a task_struct variable (no .field after).
        // The structural check should produce an ERROR containing both "directVal" and
        // "field access" in the message.
        String src = bpfClassSource("NoMemberSelectTest",
                "    @BPFFunction\n"
                + "    public int readTask(Ptr<task_struct> p) {\n"
                + "        task_struct ts = p.directVal();\n"
                + "        return 0;\n"
                + "    }\n");

        List<DiagEntry> diags = compileAndCollectDiagnostics("NoMemberSelectTest", src);

        boolean hasStructuralError = diags.stream().anyMatch(d ->
                "ERROR".equals(d.kind())
                && d.message().contains("directVal")
                && d.message().contains("field access"));

        assertTrue(hasStructuralError,
                "Expected a structural-check ERROR mentioning 'directVal' and 'field access'.\n"
                + "This test is RED in Task-4 state because Task 7 (structural check) is not yet"
                + " implemented.\n"
                + "Actual diagnostics: " + diags);
    }

    // ─── Test 3: @TrustedPtr param silences the structural check ─────────────
    //
    // Currently (Task 4) GREEN because no structural check exists yet —
    // no error is raised for any directVal() usage.
    // This test will become temporarily RED if Task 7 adds the structural check
    // WITHOUT the @TrustedPtr override, then GREEN again once both are in place.
    //
    // The fixture: a kfunc whose param is annotated @TrustedPtr task_struct
    // (not Ptr<task_struct> — the param takes the value type that directVal() returns).
    // Passing p.directVal() is Java-valid (task_struct matches task_struct).

    @Test
    void directValWithTrustedPtrParamSilent() {
        // A kfunc-shaped helper whose first param is @TrustedPtr task_struct ts.
        // Passing p.directVal() is type-correct (directVal returns task_struct).
        // The @TrustedPtr annotation tells the plugin: this is an intentional trusted
        // direct-value pass; suppress the structural check.
        String src = bpfClassSource("TrustedPtrParamTest",
                "    @BuiltinBPFFunction(\"trusted_kfunc($arg1)\")\n"
                + "    @NotUsableInJava\n"
                + "    static int trustedKfunc(@TrustedPtr task_struct ts) {\n"
                + "        throw new me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction();\n"
                + "    }\n"
                + "\n"
                + "    @BPFFunction\n"
                + "    public int useTrustedKfunc(Ptr<task_struct> p) {\n"
                + "        return trustedKfunc(p.directVal());\n"
                + "    }\n");

        List<DiagEntry> diags = compileAndCollectDiagnostics("TrustedPtrParamTest", src);

        boolean hasDirectValError = diags.stream().anyMatch(d ->
                "ERROR".equals(d.kind()) && d.message().contains("directVal"));

        assertFalse(hasDirectValError,
                "@TrustedPtr on the kfunc parameter must silence the directVal structural check.\n"
                + "Actual diagnostics: " + diags);
    }

    // ─── Test 4: @AllowDirectVal on local variable declaration silences check ─
    //
    // Currently (Task 4) GREEN because no structural check exists yet.

    @Test
    void directValWithAllowDirectValOnStatementSilent() {
        String src = bpfClassSource("AllowDirectValLocalTest",
                "    @BPFFunction\n"
                + "    public int readTask(Ptr<task_struct> p) {\n"
                + "        @AllowDirectVal task_struct ts = p.directVal();\n"
                + "        return 0;\n"
                + "    }\n");

        List<DiagEntry> diags = compileAndCollectDiagnostics("AllowDirectValLocalTest", src);

        boolean hasDirectValError = diags.stream().anyMatch(d ->
                "ERROR".equals(d.kind()) && d.message().contains("directVal"));

        assertFalse(hasDirectValError,
                "@AllowDirectVal on local variable declaration must silence the structural check.\n"
                + "Actual diagnostics: " + diags);
    }

    // ─── Test 5: @AllowDirectVal on enclosing @BPFFunction silences check ─────
    //
    // Currently (Task 4) GREEN because no structural check exists yet.

    @Test
    void directValWithAllowDirectValOnMethodSilent() {
        String src = bpfClassSource("AllowDirectValMethodTest",
                "    @AllowDirectVal\n"
                + "    @BPFFunction\n"
                + "    public int readTask(Ptr<task_struct> p) {\n"
                + "        task_struct ts = p.directVal();\n"
                + "        return 0;\n"
                + "    }\n");

        List<DiagEntry> diags = compileAndCollectDiagnostics("AllowDirectValMethodTest", src);

        boolean hasDirectValError = diags.stream().anyMatch(d ->
                "ERROR".equals(d.kind()) && d.message().contains("directVal"));

        assertFalse(hasDirectValError,
                "@AllowDirectVal on @BPFFunction method must silence the structural check.\n"
                + "Actual diagnostics: " + diags);
    }

    // ─── Test 6 (control): p.val().field still emits BPF_CORE_READ ────────────
    //
    // Regression guard: val() must continue to go through stripPtrVal() → CO-RE lifting.
    // GREEN in Task 4 state; must stay GREEN through all subsequent tasks.

    @BPF(license = "GPL")
    public static abstract class ValCoreReadFixture extends BPFProgram {

        @BPFFunction
        public int readPidViaCoreRead(Ptr<task_struct> p) {
            return p.val().pid;
        }
    }

    @Test
    void valCallStillEmitsCoreRead() {
        String c = stripped(codeOf(ValCoreReadFixture.class));
        // val() is stripped by stripPtrVal() and the result goes through CO-RE lifting.
        assertTrue(c.contains("BPF_CORE_READ(p, pid)"),
                "p.val().pid must still emit BPF_CORE_READ(p, pid).\n"
                + "Regression: Task 6 (stripPtrVal extension) must NOT affect val().\n"
                + "Got:\n" + c);
    }

    // ─── Test 7: directVal() on a non-Ptr receiver must not crash the plugin ──
    //
    // If a user-defined class happens to have a method named directVal(), the plugin
    // must not crash and must not emit the structural-check error (which only applies
    // to Ptr<T>.directVal()).
    //
    // Approach: compile a @BPFFunction in-memory that calls a @BuiltinBPFFunction method
    // named directVal() on a non-Ptr-typed value. Because the receiver is not Ptr<T>,
    // the structural check (Task 7) must not fire.
    //
    // GREEN in Task 4 state (no structural check → no crash, no false error).
    // Must stay GREEN after Task 7.

    @Test
    void directValOnNonPtrReceiverDoesNotCrash() {
        // Fixture: a @BPFFunction calls a @BuiltinBPFFunction named directVal() that lives
        // on the BPF program class itself (not on a Ptr). No Ptr receiver → no structural check.
        String src = bpfClassSource("NonPtrDirectValTest",
                "    /** A regular @BuiltinBPFFunction whose name happens to be directVal. */\n"
                + "    @BuiltinBPFFunction(\"my_helper($arg1)\")\n"
                + "    @NotUsableInJava\n"
                + "    public static int directVal(int x) {\n"
                + "        throw new me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction();\n"
                + "    }\n"
                + "\n"
                + "    @BPFFunction\n"
                + "    public int useNonPtrDirectVal(int x) {\n"
                + "        return directVal(x);\n"
                + "    }\n");

        List<DiagEntry> diags = compileAndCollectDiagnostics("NonPtrDirectValTest", src);

        // The plugin must not crash and must not emit a false structural-check error.
        boolean hasFalseDirectValError = diags.stream().anyMatch(d ->
                "ERROR".equals(d.kind())
                && d.message().contains("directVal")
                && d.message().contains("field access"));

        assertFalse(hasFalseDirectValError,
                "Non-Ptr directVal() must not trigger the structural-check error.\n"
                + "Actual diagnostics: " + diags);
    }

}
