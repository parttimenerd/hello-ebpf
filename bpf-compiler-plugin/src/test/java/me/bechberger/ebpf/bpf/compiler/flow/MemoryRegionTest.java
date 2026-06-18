package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion.*;
import static org.junit.jupiter.api.Assertions.*;

/** Lattice laws and seed-table assertions for {@link MemoryRegion}. */
class MemoryRegionTest {

    @Test
    void bottomAndTop() {
        assertEquals(UNKNOWN, UNKNOWN.bottom());
        assertEquals(CONFLICT, UNKNOWN.top());
    }

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void joinIsIdempotent(MemoryRegion r) {
        assertEquals(r, r.join(r, r));
    }

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void joinWithBottomIsIdentity(MemoryRegion r) {
        assertEquals(r, r.join(UNKNOWN, r));
        assertEquals(r, r.join(r, UNKNOWN));
    }

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void joinWithTopIsTop(MemoryRegion r) {
        assertEquals(CONFLICT, r.join(CONFLICT, r));
        assertEquals(CONFLICT, r.join(r, CONFLICT));
    }

    @Test
    void joinIsCommutative() {
        for (var a : MemoryRegion.values()) {
            for (var b : MemoryRegion.values()) {
                assertEquals(a.join(a, b), a.join(b, a),
                        () -> "join not commutative for " + a + ", " + b);
            }
        }
    }

    @Test
    void joinIsAssociative() {
        var vals = MemoryRegion.values();
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

    // ── safe-degrade rules from plan §"Mixing rules" ────────────────────────

    @Test
    void kernelTrackedJoinKernelUntrackedDegradesToUntracked() {
        assertEquals(KERNEL_UNTRACKED, KERNEL_TRACKED.join(KERNEL_TRACKED, KERNEL_UNTRACKED));
        assertEquals(KERNEL_UNTRACKED, KERNEL_TRACKED.join(KERNEL_UNTRACKED, KERNEL_TRACKED));
    }

    @Test
    void packetJoinKernelTrackedKeepsTracked() {
        assertEquals(KERNEL_TRACKED, PACKET.join(PACKET, KERNEL_TRACKED));
    }

    @Test
    void mapValueJoinKernelTrackedDegradesToTracked() {
        assertEquals(KERNEL_TRACKED, MAP_VALUE.join(MAP_VALUE, KERNEL_TRACKED));
        assertEquals(KERNEL_TRACKED, MAP_VALUE.join(KERNEL_TRACKED, MAP_VALUE));
    }

    @Test
    void stackJoinNonUserNonArenaTakesOther() {
        assertEquals(KERNEL_TRACKED, STACK.join(STACK, KERNEL_TRACKED));
        assertEquals(MAP_VALUE, STACK.join(MAP_VALUE, STACK));
        assertEquals(PACKET, STACK.join(STACK, PACKET));
    }

    @Test
    void stackJoinUserConflicts() {
        assertEquals(CONFLICT, STACK.join(STACK, USER));
        assertEquals(CONFLICT, STACK.join(USER, STACK));
    }

    @Test
    void stackJoinArenaConflicts() {
        assertEquals(CONFLICT, STACK.join(STACK, ARENA));
        assertEquals(CONFLICT, STACK.join(ARENA, STACK));
    }

    @Test
    void userJoinKernelConflicts() {
        assertEquals(CONFLICT, USER.join(USER, KERNEL_TRACKED));
        assertEquals(CONFLICT, USER.join(USER, KERNEL_UNTRACKED));
        assertEquals(CONFLICT, USER.join(USER, ARENA));
        assertEquals(CONFLICT, USER.join(USER, MAP_VALUE));
        assertEquals(CONFLICT, USER.join(USER, PACKET));
    }

    @Test
    void arenaJoinKernelConflicts() {
        assertEquals(CONFLICT, ARENA.join(ARENA, KERNEL_TRACKED));
        assertEquals(CONFLICT, ARENA.join(ARENA, KERNEL_UNTRACKED));
        assertEquals(CONFLICT, ARENA.join(ARENA, USER));
        assertEquals(CONFLICT, ARENA.join(ARENA, MAP_VALUE));
        assertEquals(CONFLICT, ARENA.join(ARENA, PACKET));
    }

    // ── partial order ──────────────────────────────────────────────────────

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void leqReflexive(MemoryRegion r) {
        assertTrue(r.leq(r, r));
    }

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void bottomLeqEverything(MemoryRegion r) {
        assertTrue(r.leq(UNKNOWN, r));
    }

    @ParameterizedTest
    @EnumSource(MemoryRegion.class)
    void everythingLeqTop(MemoryRegion r) {
        assertTrue(r.leq(r, CONFLICT));
    }

    @Test
    void leqRespectsSafeDegrade() {
        assertTrue(KERNEL_TRACKED.leq(KERNEL_TRACKED, KERNEL_UNTRACKED));
        assertTrue(PACKET.leq(PACKET, KERNEL_TRACKED));
        assertTrue(PACKET.leq(PACKET, KERNEL_UNTRACKED));
        assertTrue(MAP_VALUE.leq(MAP_VALUE, KERNEL_TRACKED));
        assertFalse(USER.leq(USER, KERNEL_TRACKED));
        assertFalse(KERNEL_TRACKED.leq(KERNEL_TRACKED, USER));
    }

    @Test
    void joinConsistentWithLeq() {
        // join(a, b) is an upper bound of both
        for (var a : MemoryRegion.values()) {
            for (var b : MemoryRegion.values()) {
                var j = a.join(a, b);
                assertTrue(a.leq(a, j) || j == CONFLICT,
                        () -> a + " not leq " + j + " (= " + a + " join " + b + ")");
                assertTrue(b.leq(b, j) || j == CONFLICT,
                        () -> b + " not leq " + j + " (= " + a + " join " + b + ")");
            }
        }
    }

    // ── deref capability flags ──────────────────────────────────────────────

    @Test
    void requiresUserReadOnlyForUser() {
        assertTrue(USER.requiresUserRead());
        for (var r : MemoryRegion.values()) {
            if (r != USER) assertFalse(r.requiresUserRead(), () -> "unexpected: " + r);
        }
    }

    @Test
    void requiresKernelReadOnlyForKernelUntracked() {
        assertTrue(KERNEL_UNTRACKED.requiresKernelRead());
        for (var r : MemoryRegion.values()) {
            if (r != KERNEL_UNTRACKED) assertFalse(r.requiresKernelRead(), () -> "unexpected: " + r);
        }
    }

    @Test
    void allowsDirectDerefSet() {
        assertTrue(KERNEL_TRACKED.allowsDirectDeref());
        assertTrue(STACK.allowsDirectDeref());
        assertTrue(ARENA.allowsDirectDeref());
        assertTrue(MAP_VALUE.allowsDirectDeref());
        assertFalse(USER.allowsDirectDeref());
        assertFalse(KERNEL_UNTRACKED.allowsDirectDeref());
        assertFalse(PACKET.allowsDirectDeref()); // bounds-checked separately
        assertFalse(UNKNOWN.allowsDirectDeref());
        assertFalse(CONFLICT.allowsDirectDeref());
    }
}
