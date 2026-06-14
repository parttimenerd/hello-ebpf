package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.flow.JavacTestSupport;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for {@link MapIdiomLintPass#detect(com.sun.source.tree.Tree)}. */
class MapIdiomLintPassTest {

    private static List<MapIdiomLintPass.Detection> detect(String source, String methodName) {
        var m = JavacTestSupport.parseMethod(source, methodName);
        return MapIdiomLintPass.detect(m.getBody());
    }

    private static boolean hasCategory(List<MapIdiomLintPass.Detection> ds, String category) {
        return ds.stream().anyMatch(d -> d.category().equals(category));
    }

    @Test
    void uncheckedBpfGetDotValIsRejected() {
        var d = detect("""
                class T {
                    void f(Map map, int k) { map.bpf_get(k).val(); }
                }
                """, "f");
        assertTrue(hasCategory(d, "map.unchecked-lookup"),
                "expected map.unchecked-lookup, got " + d);
    }

    @Test
    void uncheckedBpfGetDotFieldIsRejected() {
        var d = detect("""
                class T {
                    void f(Map map, int k) { int x = map.bpf_get(k).field; }
                }
                """, "f");
        assertTrue(hasCategory(d, "map.unchecked-lookup"));
    }

    @Test
    void bpfGetThroughLocalIsAllowed() {
        // The canonical safe pattern: lookup → null check → deref.
        var d = detect("""
                class T {
                    int f(Map map, int k) {
                        var p = map.bpf_get(k);
                        if (p == null) return 0;
                        return p.field;
                    }
                }
                """, "f");
        assertFalse(hasCategory(d, "map.unchecked-lookup"),
                "safe lookup-then-check pattern should not fire: " + d);
    }

    @Test
    void plainGetIsNotMatchedAsLookup() {
        // Map.get / List.get / Optional.get / etc must not trigger the BPF map lint.
        var d = detect("""
                class T {
                    void f(java.util.Map<String,Integer> m) { m.get("k").intValue(); }
                }
                """, "f");
        assertFalse(hasCategory(d, "map.unchecked-lookup"),
                "plain get() must not match: " + d);
    }

    @Test
    void ringbufReserveWithoutSubmitIsRejected() {
        var d = detect("""
                class T {
                    void f(Buf rb) {
                        var ev = rb.reserve();
                        if (ev == null) return;
                        ev.field = 1;
                    }
                }
                """, "f");
        assertTrue(hasCategory(d, "ringbuf.no-submit"),
                "reserve with no submit/discard should fire: " + d);
    }

    @Test
    void ringbufReserveWithSubmitIsAllowed() {
        var d = detect("""
                class T {
                    void f(Buf rb) {
                        var ev = rb.reserve();
                        if (ev == null) return;
                        ev.field = 1;
                        rb.submit(ev);
                    }
                }
                """, "f");
        assertFalse(hasCategory(d, "ringbuf.no-submit"),
                "submit() present should silence the check: " + d);
    }

    @Test
    void ringbufReserveWithDiscardIsAllowed() {
        var d = detect("""
                class T {
                    void f(Buf rb) {
                        var ev = rb.reserve();
                        rb.discard(ev);
                    }
                }
                """, "f");
        assertFalse(hasCategory(d, "ringbuf.no-submit"),
                "discard() also counts as releasing the slot: " + d);
    }

    @Test
    void cleanMethodHasNoDetections() {
        var d = detect("""
                class T {
                    int f(int x) { return x + 1; }
                }
                """, "f");
        assertTrue(d.isEmpty(), "clean method should have no detections: " + d);
    }

    @Test
    void multipleReservesWithOneSubmitSilencesCheck() {
        // KNOWN LIMITATION: the pass counts reserve/submit globally per-method, not per-ringbuf.
        // Two reserves with only one submit should ideally fire — but the heuristic accepts it.
        // This test pins current behavior so we notice if/when it changes.
        var d = detect("""
                class T {
                    void f(Buf a, Buf b) {
                        var x = a.reserve();
                        var y = b.reserve();
                        a.submit(x);   // b's slot leaks, but the heuristic can't tell
                    }
                }
                """, "f");
        assertFalse(hasCategory(d, "ringbuf.no-submit"),
                "current heuristic only checks for any submit/discard presence: " + d);
    }

    @Test
    void bpfGetThroughChainedCallIsStillFlagged() {
        // map.bpf_get(k).cast().val() — the .cast member-select sits directly on bpf_get(...),
        // so the lint catches it on the first hop. Good: chained shapes still fire.
        var d = detect("""
                class T {
                    void f(Map map, int k) { map.bpf_get(k).cast().val(); }
                }
                """, "f");
        assertTrue(hasCategory(d, "map.unchecked-lookup"),
                "chained .cast().val() should still flag because .cast sits on bpf_get(...): " + d);
    }

    @Test
    void parenthesizedBpfGetIsFlagged() {
        // Parens around the bpf_get invocation must not hide the unchecked dereference;
        // the verifier rejects it just the same.
        var d = detect("""
                class T {
                    void f(Map map, int k) { ((map.bpf_get(k))).val(); }
                }
                """, "f");
        assertTrue(hasCategory(d, "map.unchecked-lookup"),
                "parenthesized bpf_get(...).val() should still be flagged: " + d);
    }

    @Test
    void reserveWithArgumentsIsNotCounted() {
        // The ReserveCommitCounter requires reserve() to take zero args. reserve(N) won't count
        // — that's the BPFRingBuffer.reserve(size) overload, but at AST level we can't tell.
        // Pin the current shape-based behavior.
        var d = detect("""
                class T {
                    void f(Buf rb) { var x = rb.reserve(64); }
                }
                """, "f");
        assertFalse(hasCategory(d, "ringbuf.no-submit"),
                "reserve(N) is not flagged because counter only matches reserve() with zero args: " + d);
    }
}
