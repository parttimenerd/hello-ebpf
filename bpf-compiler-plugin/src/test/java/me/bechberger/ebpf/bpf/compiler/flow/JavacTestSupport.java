package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;

import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import java.net.URI;
import java.util.List;

/** Minimal helper to parse a Java source string and pull out a {@link MethodTree}. */
public final class JavacTestSupport {

    private JavacTestSupport() {}

    /** Parse a single class source and return the first method whose name is {@code methodName}. */
    public static MethodTree parseMethod(String source, String methodName) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("no system javac available");
        var fileObject = new SimpleJavaFileObject(URI.create("mem:///Test.java"), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) { return source; }
        };
        var task = (com.sun.source.util.JavacTask) compiler.getTask(
                null, null, null, List.of(), null, List.of(fileObject));
        try {
            Iterable<? extends CompilationUnitTree> units = task.parse();
            for (var cu : units) {
                for (var typeDecl : cu.getTypeDecls()) {
                    if (typeDecl instanceof ClassTree cls) {
                        for (var m : cls.getMembers()) {
                            if (m instanceof MethodTree mt
                                    && mt.getName().toString().equals(methodName)) {
                                return mt;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("parse failed: " + e, e);
        }
        throw new AssertionError("method not found: " + methodName);
    }
}
