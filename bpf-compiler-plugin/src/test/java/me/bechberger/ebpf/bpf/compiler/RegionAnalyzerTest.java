package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.AnalysisContext;
import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the full region analysis in {@link RegionAnalyzer}.
 *
 * <p>Complements {@link RegionAnalyzerSeedTableTest} which only tests the
 * {@code regionFromAnnotations} helper. These tests exercise the actual
 * dataflow: method-call seeding, member-select inheritance, and region-mixing
 * CONFLICT detection.
 *
 * <p>Note: in parse-only mode (no type-check), method symbols are unavailable,
 * so method-call seeding that relies on symbol names (bpf_get, castUser, etc.)
 * is tested via the syntactic name path in {@link RegionAnalyzer#evalCall}.
 */
class RegionAnalyzerTest {

    private static List<RegionAnalyzer.Detection> detect(String source, String methodName) {
        return RegionAnalyzer.detect(JavacTestSupport.parseMethod(source, methodName));
    }

    private static AnalysisContext analyze(String source, String methodName) {
        var ctx = new AnalysisContext();
        RegionAnalyzer.detect(JavacTestSupport.parseMethod(source, methodName), ctx);
        return ctx;
    }

    // ── Parameter annotation seeding ────────────────────────────────────

    @Test
    void annotatedParamsAreSeededIntoRegionMap() {
        // @BPFUserMemory param should yield USER region for identifiers that refer to it.
        // We verify via detection ctx — if there's no CONFLICT, the seeding worked.
        var d = detect("""
                class T {
                    @interface BPFUserMemory {}
                    void f(@BPFUserMemory Object user) {
                        Object x = user;  // should not fire: same region
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "same-region assignment should not produce a mixing error");
    }

    // ── Method-call seeding (syntactic name path) ─────────────────────

    @Test
    void bpfGetCallYieldsMapValueRegion() {
        // `bpf_get(k)` → MAP_VALUE. We detect this by assigning the result
        // to a variable that is then re-assigned a different-region value.
        var d = detect("""
                class T {
                    @interface BPFUserMemory {}
                    Object bpf_get(Object k) { return null; }
                    void f(@BPFUserMemory Object user) {
                        Object entry = bpf_get(null);  // MAP_VALUE
                        entry = user;                   // USER — CONFLICT expected
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "MAP_VALUE + USER mixing should produce one region-mixing detection");
        assertTrue(d.get(0).message().contains("MAP_VALUE") || d.get(0).message().contains("USER"),
                "detection message should mention the conflicting regions: " + d.get(0).message());
    }

    @Test
    void castUserCallYieldsUserRegion() {
        // castUser() → USER. Assigning a MAP_VALUE into a USER variable triggers CONFLICT.
        var d = detect("""
                class T {
                    Object bpf_get(Object k) { return null; }
                    Object castUser(Object p) { return p; }
                    void f() {
                        Object entry = bpf_get(null);  // MAP_VALUE
                        entry = castUser(entry);        // USER — CONFLICT
                    }
                }
                """, "f");
        assertEquals(1, d.size(), "MAP_VALUE reassigned to USER should produce a mixing detection");
    }

    // ── Member-select inheritance ─────────────────────────────────────

    @Test
    void memberSelectOnKernelTrackedYieldsKernelUntracked() {
        // A KERNEL_TRACKED pointer's field → KERNEL_UNTRACKED.
        // We can verify this indirectly: KERNEL_TRACKED field then mixing with MAP_VALUE.
        var d = detect("""
                class T {
                    @interface BPFKernelMemory {}
                    Object bpf_get(Object k) { return null; }
                    void f(@BPFKernelMemory Object kt) {
                        Object nested = kt.inner;      // KERNEL_UNTRACKED (via member-select)
                        nested = bpf_get(null);        // MAP_VALUE — CONFLICT
                    }
                }
                """, "f");
        assertEquals(1, d.size(),
                "KERNEL_TRACKED.field + MAP_VALUE mixing should detect region conflict");
    }

    // ── Region mixing → CONFLICT detection ───────────────────────────

    @Test
    void mixingUserAndMapValueProducesConflict() {
        var d = detect("""
                class T {
                    @interface BPFUserMemory {}
                    Object bpf_get(Object k) { return null; }
                    void f(@BPFUserMemory Object u) {
                        Object x = u;           // USER
                        x = bpf_get(null);      // MAP_VALUE — CONFLICT
                    }
                }
                """, "f");
        assertEquals(1, d.size());
        assertEquals("region.mixing", d.get(0).category());
    }

    @Test
    void sameRegionAssignmentIsClean() {
        var d = detect("""
                class T {
                    @interface BPFUserMemory {}
                    void f(@BPFUserMemory Object a, @BPFUserMemory Object b) {
                        Object x = a;
                        x = b;  // same region — OK
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "same-region reassignment must not produce a mixing error");
    }

    @Test
    void unknownRegionDoesNotConflict() {
        var d = detect("""
                class T {
                    Object createThing() { return null; }
                    void f() {
                        Object x = createThing();  // UNKNOWN
                        x = createThing();          // UNKNOWN — no CONFLICT
                    }
                }
                """, "f");
        assertEquals(0, d.size(), "UNKNOWN ⊔ UNKNOWN is UNKNOWN — no detection");
    }

    // ── Message format ───────────────────────────────────────────────────

    @Test
    void mixingDetectionMessageIsFourPart() {
        var d = detect("""
                class T {
                    @interface BPFUserMemory {}
                    Object bpf_get(Object k) { return null; }
                    void f(@BPFUserMemory Object u) {
                        Object x = u;
                        x = bpf_get(null);
                    }
                }
                """, "f");
        assertEquals(1, d.size());
        var msg = d.get(0).message();
        assertTrue(msg.contains("Why:"), "message must contain Why: — got:\n" + msg);
        assertTrue(msg.contains("Fix:"), "message must contain Fix: — got:\n" + msg);
        assertTrue(msg.contains("See:"), "message must contain See: — got:\n" + msg);
    }

    // ── Probe-read reseeding ─────────────────────────────────────────────

    @Test
    void probeReadKernelReseedsDstAsStack() {
        // After bpf_probe_read_kernel(dst, ...), dst should be STACK.
        // Re-assigning a MAP_VALUE into dst afterward would be MAP_VALUE ≠ STACK → CONFLICT.
        var d = detect("""
                class T {
                    void bpf_probe_read_kernel(Object dst, int sz, Object src) {}
                    Object bpf_get(Object k) { return null; }
                    void f(Object src) {
                        byte[] dst = new byte[16];      // UNKNOWN
                        bpf_probe_read_kernel(dst, 16, src);  // dst → STACK
                        dst = bpf_get(null);            // MAP_VALUE — CONFLICT with STACK
                    }
                }
                """, "f");
        assertEquals(1, d.size(),
                "STACK (post probe-read) + MAP_VALUE should produce a mixing detection");
    }

    // ── Clean method ─────────────────────────────────────────────────────

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("class T { void f(int x) { int y = x + 1; } }", "f");
        assertEquals(0, d.size());
    }
}
