package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Tests for the pointwise {@link MapLattice} lifting. */
class MapLatticeTest {

    private final MapLattice<String, NullabilityValue> lat = new MapLattice<>(NullabilityValue.NON_NULL);

    @Test
    void bottomIsEmpty() {
        var b = lat.bottom();
        assertTrue(b.isEmpty());
        assertEquals(NullabilityValue.NON_NULL, b.get("missing"));
    }

    @Test
    void putReturnsNewEnv() {
        var e0 = lat.empty();
        var e1 = e0.put("x", NullabilityValue.MAYBE_NULL);
        assertTrue(e0.isEmpty());
        assertEquals(NullabilityValue.MAYBE_NULL, e1.get("x"));
    }

    @Test
    void removeReturnsNewEnv() {
        var e1 = lat.empty().put("x", NullabilityValue.MAYBE_NULL);
        var e2 = e1.remove("x");
        assertEquals(NullabilityValue.MAYBE_NULL, e1.get("x"));
        assertEquals(NullabilityValue.NON_NULL, e2.get("x")); // missing → bottom
    }

    @Test
    void joinIsPointwise() {
        var a = lat.empty().put("x", NullabilityValue.NON_NULL).put("y", NullabilityValue.UNKNOWN);
        var b = lat.empty().put("x", NullabilityValue.MAYBE_NULL).put("z", NullabilityValue.UNKNOWN);
        var j = lat.join(a, b);
        assertEquals(NullabilityValue.MAYBE_NULL, j.get("x"));
        assertEquals(NullabilityValue.UNKNOWN, j.get("y"));
        assertEquals(NullabilityValue.UNKNOWN, j.get("z"));
    }

    @Test
    void joinWithEmptyIsIdentity() {
        var a = lat.empty().put("x", NullabilityValue.MAYBE_NULL);
        assertEquals(a, lat.join(a, lat.empty()));
        assertEquals(a, lat.join(lat.empty(), a));
    }

    @Test
    void leqMissingKeyTreatedAsBottom() {
        var a = lat.empty().put("x", NullabilityValue.NON_NULL); // bottom value
        var b = lat.empty(); // missing key ≡ bottom too
        assertTrue(lat.leq(a, b));
        assertTrue(lat.leq(b, a));
    }

    @Test
    void leqMissingVsHigherFails() {
        var a = lat.empty().put("x", NullabilityValue.MAYBE_NULL); // top value
        var b = lat.empty();
        assertFalse(lat.leq(a, b)); // a's MAYBE_NULL not leq missing(=NON_NULL)
        assertTrue(lat.leq(b, a));
    }

    @Test
    void leqPointwise() {
        var a = lat.empty().put("x", NullabilityValue.NON_NULL).put("y", NullabilityValue.UNKNOWN);
        var b = lat.empty().put("x", NullabilityValue.MAYBE_NULL).put("y", NullabilityValue.MAYBE_NULL);
        assertTrue(lat.leq(a, b));
        assertFalse(lat.leq(b, a));
    }

    @Test
    void fromMapAndToMutableRoundtrip() {
        Map<String, NullabilityValue> seed = new HashMap<>();
        seed.put("x", NullabilityValue.MAYBE_NULL);
        seed.put("y", NullabilityValue.UNKNOWN);
        var env = lat.fromMap(seed);
        var mut = lat.toMutable(env);
        assertEquals(seed, mut);
        // Mutating the seed must not affect the env (defensive copy).
        seed.put("x", NullabilityValue.NON_NULL);
        assertEquals(NullabilityValue.MAYBE_NULL, env.get("x"));
    }

    @Test
    void widenDefaultsToJoinForFiniteLattices() {
        var a = lat.empty().put("x", NullabilityValue.NON_NULL);
        var b = lat.empty().put("x", NullabilityValue.MAYBE_NULL);
        var w = lat.widen(a, b);
        assertEquals(NullabilityValue.MAYBE_NULL, w.get("x"));
    }

    @Test
    void singletonAndEqualsAndHash() {
        var a = lat.singleton("x", NullabilityValue.MAYBE_NULL);
        var b = lat.empty().put("x", NullabilityValue.MAYBE_NULL);
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void meetIsPointwiseAndDropsKeysMissingFromEither() {
        // The current meet implementation only retains keys present in BOTH inputs — keys only
        // in one are dropped. Document the behavior since it differs from a strict
        // "missing == bottom" reading (which would say meet should keep them at bottom).
        var a = lat.empty()
                .put("x", NullabilityValue.UNKNOWN)
                .put("y", NullabilityValue.MAYBE_NULL);
        var b = lat.empty()
                .put("x", NullabilityValue.MAYBE_NULL)
                .put("z", NullabilityValue.UNKNOWN);
        var m = lat.meet(a, b);
        assertEquals(NullabilityValue.UNKNOWN, m.get("x")); // meet of UNKNOWN, MAYBE_NULL
        assertEquals(NullabilityValue.NON_NULL, m.get("y")); // dropped → missing → bottom
        assertEquals(NullabilityValue.NON_NULL, m.get("z")); // dropped → missing → bottom
        assertFalse(m.containsKey("y"));
        assertFalse(m.containsKey("z"));
    }
}
