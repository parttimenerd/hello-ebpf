package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static me.bechberger.ebpf.bpf.compiler.flow.NullabilityValue.*;
import static org.junit.jupiter.api.Assertions.*;

/** Lattice laws for {@link NullabilityValue}. */
class NullabilityValueTest {

    @Test
    void bottomAndTop() {
        assertEquals(NON_NULL, NON_NULL.bottom());
        assertEquals(MAYBE_NULL, NON_NULL.top());
    }

    @Test
    void joinSemantics() {
        assertEquals(NON_NULL, NON_NULL.join(NON_NULL, NON_NULL));
        assertEquals(UNKNOWN, NON_NULL.join(NON_NULL, UNKNOWN));
        assertEquals(MAYBE_NULL, NON_NULL.join(NON_NULL, MAYBE_NULL));
        assertEquals(MAYBE_NULL, NON_NULL.join(UNKNOWN, MAYBE_NULL));
        assertEquals(UNKNOWN, NON_NULL.join(UNKNOWN, UNKNOWN));
    }

    @Test
    void meetSemantics() {
        assertEquals(NON_NULL, NON_NULL.meet(NON_NULL, MAYBE_NULL));
        assertEquals(NON_NULL, NON_NULL.meet(NON_NULL, UNKNOWN));
        assertEquals(UNKNOWN, NON_NULL.meet(UNKNOWN, MAYBE_NULL));
        assertEquals(MAYBE_NULL, NON_NULL.meet(MAYBE_NULL, MAYBE_NULL));
    }

    @Test
    void leqIsTotalOrderOnTheChain() {
        assertTrue(NON_NULL.leq(NON_NULL, NON_NULL));
        assertTrue(NON_NULL.leq(NON_NULL, UNKNOWN));
        assertTrue(NON_NULL.leq(NON_NULL, MAYBE_NULL));
        assertTrue(NON_NULL.leq(UNKNOWN, MAYBE_NULL));
        assertFalse(NON_NULL.leq(MAYBE_NULL, NON_NULL));
        assertFalse(NON_NULL.leq(MAYBE_NULL, UNKNOWN));
        assertFalse(NON_NULL.leq(UNKNOWN, NON_NULL));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void joinIsCommutative(NullabilityValue a) {
        for (var b : NullabilityValue.values()) {
            assertEquals(a.join(a, b), a.join(b, a));
        }
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void joinAndMeetAbsorb(NullabilityValue a) {
        for (var b : NullabilityValue.values()) {
            // a ⊔ (a ⊓ b) = a ; a ⊓ (a ⊔ b) = a
            assertEquals(a, a.join(a, a.meet(a, b)));
            assertEquals(a, a.meet(a, a.join(a, b)));
        }
    }

    @Test
    void isSafeOnlyForNonNull() {
        assertTrue(NON_NULL.isSafe());
        assertFalse(UNKNOWN.isSafe());
        assertFalse(MAYBE_NULL.isSafe());
    }

    // ── lattice laws (parity with MemoryRegionTest) ────────────────────────

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void joinIsIdempotent(NullabilityValue v) {
        assertEquals(v, v.join(v, v));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void meetIsIdempotent(NullabilityValue v) {
        assertEquals(v, v.meet(v, v));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void joinWithBottomIsIdentity(NullabilityValue v) {
        assertEquals(v, v.join(NON_NULL, v));
        assertEquals(v, v.join(v, NON_NULL));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void joinWithTopIsTop(NullabilityValue v) {
        assertEquals(MAYBE_NULL, v.join(MAYBE_NULL, v));
        assertEquals(MAYBE_NULL, v.join(v, MAYBE_NULL));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void meetWithTopIsIdentity(NullabilityValue v) {
        assertEquals(v, v.meet(MAYBE_NULL, v));
        assertEquals(v, v.meet(v, MAYBE_NULL));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void meetWithBottomIsBottom(NullabilityValue v) {
        assertEquals(NON_NULL, v.meet(NON_NULL, v));
        assertEquals(NON_NULL, v.meet(v, NON_NULL));
    }

    @Test
    void joinIsAssociative() {
        var vals = NullabilityValue.values();
        for (var a : vals) {
            for (var b : vals) {
                for (var c : vals) {
                    var l = a.join(a.join(a, b), c);
                    var r = a.join(a, a.join(b, c));
                    assertEquals(l, r,
                            () -> "join not associative for " + a + ", " + b + ", " + c);
                }
            }
        }
    }

    @Test
    void meetIsAssociative() {
        var vals = NullabilityValue.values();
        for (var a : vals) {
            for (var b : vals) {
                for (var c : vals) {
                    var l = a.meet(a.meet(a, b), c);
                    var r = a.meet(a, a.meet(b, c));
                    assertEquals(l, r,
                            () -> "meet not associative for " + a + ", " + b + ", " + c);
                }
            }
        }
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void leqReflexive(NullabilityValue v) {
        assertTrue(v.leq(v, v));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void bottomLeqEverything(NullabilityValue v) {
        assertTrue(v.leq(NON_NULL, v));
    }

    @ParameterizedTest
    @EnumSource(NullabilityValue.class)
    void everythingLeqTop(NullabilityValue v) {
        assertTrue(v.leq(v, MAYBE_NULL));
    }

    @Test
    void leqIsTransitive() {
        var vals = NullabilityValue.values();
        for (var a : vals) {
            for (var b : vals) {
                for (var c : vals) {
                    if (a.leq(a, b) && a.leq(b, c)) {
                        assertTrue(a.leq(a, c),
                                () -> "leq not transitive: " + a + " ≤ " + b + " ≤ " + c);
                    }
                }
            }
        }
    }

    @Test
    void joinConsistentWithLeq() {
        // join(a, b) is an upper bound of both operands.
        for (var a : NullabilityValue.values()) {
            for (var b : NullabilityValue.values()) {
                var j = a.join(a, b);
                assertTrue(a.leq(a, j),
                        () -> a + " not leq " + j + " (= " + a + " join " + b + ")");
                assertTrue(b.leq(b, j),
                        () -> b + " not leq " + j + " (= " + a + " join " + b + ")");
            }
        }
    }

    @Test
    void meetConsistentWithLeq() {
        // meet(a, b) is a lower bound of both operands.
        for (var a : NullabilityValue.values()) {
            for (var b : NullabilityValue.values()) {
                var m = a.meet(a, b);
                assertTrue(a.leq(m, a),
                        () -> m + " not leq " + a + " (= " + a + " meet " + b + ")");
                assertTrue(a.leq(m, b),
                        () -> m + " not leq " + b + " (= " + a + " meet " + b + ")");
            }
        }
    }
}
