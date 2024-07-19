package me.bechberger.ebpf.bpf.processor;

import me.bechberger.ebpf.bpf.processor.CompilerErrorProcessor.CompilerError;
import me.bechberger.ebpf.bpf.processor.CompilerErrorProcessor.CompilerErrorsPerFile;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class CompilerErrorProcessorTest {

    @Test
    public void testFileNotFound() {
        var message = """
                <stdin>:2:10: fatal error: 'bpf/bpf_helpers.hh' file not found
                #include <bpf/bpf_helpers.hh>
                         ^~~~~~~~~~~~~~~~~~~~
                1 error generated.
                """;
        var res = CompilerErrorProcessor.fromClangOutput(message, Path.of("/file.c"));
        assertEquals(1, res.errors().size());
        var error = (CompilerErrorsPerFile) res.errors().getFirst();
        assertEquals(1, error.errors().size());
        var compilerError = error.errors().getFirst();
        assertEquals("/file.c", compilerError.file().toString());
        assertEquals(2, compilerError.line());
        assertEquals(10, compilerError.column());
        assertEquals("fatal error: 'bpf/bpf_helpers.hh' file not found", compilerError.header());
        assertEquals("""
                #include <bpf/bpf_helpers.hh>
                         ^~~~~~~~~~~~~~~~~~~~
                1 error generated.
                """.strip(), compilerError.body());
        assertTrue(compilerError.isFatal());
        assertFalse(compilerError.isWarning());
        assertFalse(compilerError.isError());
    }

    @Test
    public void testFunctionHeaderError() {
        var message = """
                <stdin>:6:12: error: expected function body after function declarator
                int func() sdf;
                           ^
                1 error generated.
                """;
        var res = CompilerErrorProcessor.fromClangOutput(message, Path.of("a/file.c"));
        assertEquals(1, res.errors().size());
        var error = (CompilerErrorsPerFile) res.errors().getFirst();
        assertEquals(1, error.errors().size());
        var compilerError = error.errors().getFirst();
        assertEquals("a/file.c", compilerError.file().toString());
        assertEquals(6, compilerError.line());
        assertEquals(12, compilerError.column());
        assertEquals("error: expected function body after function declarator", compilerError.header());
        assertEquals("""
                int func() sdf;
                           ^
                1 error generated.
                """.strip(), compilerError.body());
        assertFalse(compilerError.isFatal());
        assertFalse(compilerError.isWarning());
        assertTrue(compilerError.isError());
    }

    @Test
    public void testUndeclaredFunctionError() {
        var message = """
                <stdin>:7:12: error: call to undeclared function 'int2'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
                    return int2();
                           ^
                """;
        var res = CompilerErrorProcessor.fromClangOutput(message, Path.of("a/file.c"));
        assertEquals(1, res.errors().size());
        var error = (CompilerErrorsPerFile) res.errors().getFirst();
        assertEquals(1, error.errors().size());
        var compilerError = error.errors().getFirst();
        assertEquals(7, compilerError.line());
        assertEquals(12, compilerError.column());
        assertEquals("error: call to undeclared function 'int2'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]", compilerError.header());
        assertEquals("""
                    return int2();
                           ^
                """, compilerError.body() + "\n");
    }

    @Test
    public void testMultipleErrors() {
        var message = """
                <stdin>:7:12: error: call to undeclared function 'int2'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
                    return int2();
                           ^
                <stdin>:10:5: error: redefinition of 'func'
                int func() {
                    ^
                <stdin>:6:5: note: previous definition is here
                int func() {
                    ^
                2 errors generated.
                """;
        var res = CompilerErrorProcessor.fromClangOutput(message, Path.of("a/file.c"));
        assertEquals(1, res.errors().size());
        var error = (CompilerErrorsPerFile) res.errors().getFirst();
        assertEquals(3, error.errors().size());
        var compilerError = error.errors().getFirst();
        assertEquals(7, compilerError.line());
        assertEquals(12, compilerError.column());
        assertEquals("error: call to undeclared function 'int2'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]", compilerError.header());
        assertEquals("""
                    return int2();
                           ^
                """, compilerError.body() + "\n");
        compilerError = error.errors().get(1);
        assertEquals(10, compilerError.line());
        assertEquals(5, compilerError.column());
        assertEquals("error: redefinition of 'func'", compilerError.header());
        assertEquals("""
                int func() {
                    ^
                """.strip(), compilerError.body());
        compilerError = error.errors().get(2);
        assertEquals(6, compilerError.line());
        assertEquals(5, compilerError.column());
        assertEquals("note: previous definition is here", compilerError.header());
        assertEquals("""
                int func() {
                    ^
                2 errors generated.
                """.strip(), compilerError.body());
        assertTrue(compilerError.isNote());
    }
}
