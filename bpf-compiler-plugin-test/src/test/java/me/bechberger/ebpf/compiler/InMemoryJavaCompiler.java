package me.bechberger.ebpf.compiler;

import javax.tools.*;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Minimal in-memory Java compiler harness. Used to compile fixture sources that
 * deliberately trigger annotation-processor errors and assert the diagnostic
 * messages.
 */
public final class InMemoryJavaCompiler {

    /** Result of one compilation attempt. */
    public record Result(boolean success,
                         List<Diagnostic<? extends JavaFileObject>> diagnostics,
                         String compilerOutput,
                         java.util.Map<String, String> generatedSources) {

        /** Backwards-compatible constructor without generated-source capture. */
        public Result(boolean success,
                      List<Diagnostic<? extends JavaFileObject>> diagnostics,
                      String compilerOutput) {
            this(success, diagnostics, compilerOutput, java.util.Map.of());
        }

        /** All error-level diagnostic messages joined with newlines. */
        public String errorMessages() {
            var sb = new StringBuilder();
            for (var d : diagnostics) {
                if (d.getKind() == Diagnostic.Kind.ERROR) {
                    sb.append(d.getMessage(Locale.ROOT)).append('\n');
                }
            }
            return sb.toString();
        }

        /** Throws if compilation succeeded — used by error-tests. */
        public Result requireFailure(String why) {
            if (success) {
                throw new AssertionError(why + " — but compilation succeeded.\n"
                        + "Compiler output:\n" + compilerOutput);
            }
            return this;
        }

        /** Throws if compilation failed — used by codegen tests. */
        public Result requireSuccess(String why) {
            if (!success) {
                throw new AssertionError(why + " — compilation failed.\n"
                        + "Diagnostics:\n" + errorMessages()
                        + "Compiler output:\n" + compilerOutput);
            }
            return this;
        }

        /** Retrieve a generated source file by its fully-qualified class name. */
        public java.util.Optional<String> generatedSource(String fqcn) {
            return java.util.Optional.ofNullable(generatedSources.get(fqcn));
        }
    }

    /** A single source file pinned to a fully-qualified Java name. */
    public record Source(String fqn, String body) {
        JavaFileObject toFileObject() {
            return new SimpleJavaFileObject(
                    URI.create("string:///" + fqn.replace('.', '/') + ".java"),
                    JavaFileObject.Kind.SOURCE) {
                @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                    return body;
                }
            };
        }
    }

    private InMemoryJavaCompiler() {}

    /**
     * Compile {@code sources} with the given annotation processor, returning the
     * full diagnostic list. The current process classpath is reused so framework
     * types (BPFProgram, @BPF, etc.) resolve.
     */
    public static Result compile(List<Source> sources, javax.annotation.processing.Processor processor) {
        var compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "No system Java compiler available — run tests on a JDK, not a JRE.");
        }
        var diagnostics = new DiagnosticCollector<JavaFileObject>();
        var fileManager = compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8);

        var compilationUnits = new ArrayList<JavaFileObject>();
        for (var s : sources) compilationUnits.add(s.toFileObject());

        // Direct generated sources/classes/resources to a tempdir so test runs don't
        // leak files into the module's working directory.
        java.nio.file.Path tmp;
        try {
            tmp = java.nio.file.Files.createTempDirectory("hello-ebpf-shared-from-test-");
        } catch (IOException e) {
            throw new RuntimeException("could not create temp dir for compiler output", e);
        }
        List<String> options = List.of(
                "-classpath", System.getProperty("java.class.path"),
                "-proc:only",
                "-s", tmp.toString(),
                "-d", tmp.toString()
        );

        var output = new StringWriter();
        var task = compiler.getTask(output, fileManager, diagnostics, options, null, compilationUnits);
        task.setProcessors(List.of(processor));

        boolean success;
        java.util.Map<String, String> generatedSources = new java.util.LinkedHashMap<>();
        try {
            success = task.call();
            // Collect all generated .java files before we wipe the temp dir.
            try {
                java.nio.file.Files.walk(tmp)
                        .filter(java.nio.file.Files::isRegularFile)
                        .filter(p -> p.toString().endsWith(".java"))
                        .forEach(p -> {
                            try {
                                String rel = tmp.relativize(p).toString();
                                // Strip .java and convert path separators to dots.
                                String fqcn = rel.substring(0, rel.length() - ".java".length())
                                        .replace(java.io.File.separatorChar, '.');
                                generatedSources.put(fqcn, java.nio.file.Files.readString(p));
                            } catch (IOException ignored) {}
                        });
            } catch (IOException ignored) {}
        } finally {
            try { fileManager.close(); } catch (IOException ignored) {}
            // Best-effort cleanup of the temp tree.
            try {
                java.nio.file.Files.walk(tmp)
                        .sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> { try { java.nio.file.Files.deleteIfExists(p); } catch (IOException ignored) {} });
            } catch (IOException ignored) {}
        }
        return new Result(success, diagnostics.getDiagnostics(), output.toString(), generatedSources);
    }
}
