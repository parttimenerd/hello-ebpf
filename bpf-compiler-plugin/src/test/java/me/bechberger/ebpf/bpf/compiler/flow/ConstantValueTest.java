package me.bechberger.ebpf.bpf.compiler.flow;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for the {@link ConstantValue} lattice. */
class ConstantValueTest {

    @Test
    void bottomIsTheLeastElement() {
        assertTrue(ConstantValue.BOTTOM.isBottom());
        assertTrue(ConstantValue.BOTTOM.leq(ConstantValue.BOTTOM, ConstantValue.TOP));
        assertTrue(ConstantValue.BOTTOM.leq(ConstantValue.BOTTOM, ConstantValue.constant(7)));
        assertTrue(ConstantValue.BOTTOM.leq(ConstantValue.BOTTOM, ConstantValue.BOTTOM));
    }

    @Test
    void topIsTheGreatestElement() {
        assertTrue(ConstantValue.TOP.isTop());
        assertTrue(ConstantValue.TOP.leq(ConstantValue.constant(7), ConstantValue.TOP));
        assertTrue(ConstantValue.TOP.leq(ConstantValue.BOTTOM, ConstantValue.TOP));
        assertTrue(ConstantValue.TOP.leq(ConstantValue.TOP, ConstantValue.TOP));
    }

    @Test
    void joinOfEqualConstantsIsTheConstant() {
        var c = ConstantValue.constant(42);
        assertEquals(c, ConstantValue.BOTTOM.join(c, ConstantValue.constant(42)));
    }

    @Test
    void joinOfDifferentConstantsIsTop() {
        var a = ConstantValue.constant(1);
        var b = ConstantValue.constant(2);
        assertEquals(ConstantValue.TOP, ConstantValue.BOTTOM.join(a, b));
    }

    @Test
    void joinWithBottomIsIdentity() {
        var c = ConstantValue.constant(99);
        assertEquals(c, ConstantValue.BOTTOM.join(c, ConstantValue.BOTTOM));
        assertEquals(c, ConstantValue.BOTTOM.join(ConstantValue.BOTTOM, c));
    }

    @Test
    void joinWithTopIsTop() {
        assertEquals(ConstantValue.TOP, ConstantValue.BOTTOM.join(ConstantValue.constant(5), ConstantValue.TOP));
    }

    @Test
    void meetOfDifferentConstantsIsBottom() {
        var a = ConstantValue.constant(1);
        var b = ConstantValue.constant(2);
        assertEquals(ConstantValue.BOTTOM, a.meet(a, b));
    }

    @Test
    void leqHonorsConstantEquality() {
        var a = ConstantValue.constant(7);
        assertTrue(a.leq(a, a));
        assertFalse(a.leq(a, ConstantValue.constant(8)));
    }

    @Test
    void preallocatedZeroAndOneEqualConstructed() {
        assertEquals(ConstantValue.constant(0L), ConstantValue.ZERO);
        assertEquals(ConstantValue.constant(1L), ConstantValue.ONE);
    }

    @Test
    void asLongOnNonConstantThrows() {
        assertThrows(IllegalStateException.class, ConstantValue.TOP::asLong);
        assertThrows(IllegalStateException.class, ConstantValue.BOTTOM::asLong);
    }
}
