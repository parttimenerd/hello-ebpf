package me.bechberger.ebpf.bpf.compiler;

import com.sun.source.tree.MethodTree;
import com.sun.source.tree.VariableTree;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the testable static helpers in {@link RegionAnalyzer}. The full end-to-end
 * pipeline (which needs a {@code CompilerPlugin} + {@code Trees}) lives in the integration-test
 * module. Here we verify only the seed-table mapping from parameter annotations to regions.
 */
class RegionAnalyzerSeedTableTest {

    private static VariableTree firstParam(String src, String methodName) {
        MethodTree m = JavacTestSupport.parseMethod(src, methodName);
        assertFalse(m.getParameters().isEmpty(), "expected at least one parameter");
        return m.getParameters().get(0);
    }

    @Test
    void plainParamHasUnknownRegion() {
        var p = firstParam("""
                class T { void f(Object x) { } }
                """, "f");
        assertEquals(MemoryRegion.UNKNOWN, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void bpfUserMemoryAnnotationMapsToUserRegion() {
        // Use a stub annotation with the right simple name — the lookup is by simple name.
        var p = firstParam("""
                class T {
                    @interface BPFUserMemory {}
                    void f(@BPFUserMemory Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.USER, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void bpfKernelMemoryAnnotationMapsToKernelUntracked() {
        var p = firstParam("""
                class T {
                    @interface BPFKernelMemory {}
                    void f(@BPFKernelMemory Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.KERNEL_UNTRACKED, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void inArenaAnnotationMapsToArena() {
        var p = firstParam("""
                class T {
                    @interface InArena {}
                    void f(@InArena Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.ARENA, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void unrecognizedAnnotationLeavesRegionUnknown() {
        var p = firstParam("""
                class T {
                    @interface SomeOther {}
                    void f(@SomeOther Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.UNKNOWN, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void firstRecognisedAnnotationWinsOnMultiAnnotated() {
        // Multiple annotations: the loop returns on the first match. BPFUserMemory comes first
        // textually so it should win. (Document the current behavior; in practice we never
        // expect a single param to be tagged with two region annotations.)
        var p = firstParam("""
                class T {
                    @interface BPFUserMemory {}
                    @interface InArena {}
                    void f(@BPFUserMemory @InArena Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.USER, RegionAnalyzer.regionFromAnnotations(p));
    }

    @Test
    void worksOnLocalVariableTree() {
        // The helper takes any VariableTree, not just a parameter — verify with a local.
        var m = JavacTestSupport.parseMethod("""
                class T {
                    @interface BPFKernelMemory {}
                    void f() {
                        @BPFKernelMemory Object local = null;
                    }
                }
                """, "f");
        // Find the local DECL by walking the method body.
        VariableTree local = (VariableTree) ((com.sun.source.tree.BlockTree) m.getBody())
                .getStatements().get(0);
        assertEquals("local", local.getName().toString());
        assertEquals(MemoryRegion.KERNEL_UNTRACKED, RegionAnalyzer.regionFromAnnotations(local));
    }

    @Test
    void fullyQualifiedAnnotationMapsCorrectly() {
        // The helper extracts the simple name from a dotted FQN — verify a written-out FQN works.
        var p = firstParam("""
                package p;
                class T {
                    void f(@some.pkg.BPFUserMemory Object x) { }
                }
                """, "f");
        assertEquals(MemoryRegion.USER, RegionAnalyzer.regionFromAnnotations(p));
    }
}
