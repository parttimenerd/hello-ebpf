package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.PtrCoercionInference.Coercion;
import me.bechberger.ebpf.bpf.compiler.flow.MemoryRegion;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Unit tests for the pure helpers of {@link PtrCoercionInference}. */
class PtrCoercionInferenceTest {

    @Test
    void noCoercionWhenShapesMatch() {
        assertEquals(Coercion.NONE, PtrCoercionInference.classifyCoercion(false, false));
        assertEquals(Coercion.NONE, PtrCoercionInference.classifyCoercion(true, true));
    }

    @Test
    void takeAddressWhenParamIsPtr() {
        assertEquals(Coercion.TAKE_ADDRESS, PtrCoercionInference.classifyCoercion(false, true));
    }

    @Test
    void dereferenceWhenArgIsPtr() {
        assertEquals(Coercion.DEREFERENCE, PtrCoercionInference.classifyCoercion(true, false));
    }

    @Test
    void unknownParamRegionAlwaysProceeds() {
        for (var r : MemoryRegion.values()) {
            if (r == MemoryRegion.CONFLICT) continue;
            assertTrue(
                    PtrCoercionInference.regionAllowsCoercion(r, MemoryRegion.UNKNOWN),
                    "expected coercion for expr=" + r + ", param=UNKNOWN");
        }
    }

    @Test
    void sameRegionProceeds() {
        for (var r : MemoryRegion.values()) {
            if (r == MemoryRegion.CONFLICT) continue;
            assertTrue(
                    PtrCoercionInference.regionAllowsCoercion(r, r),
                    "expected same-region " + r + " to proceed");
        }
    }

    @Test
    void stackToUserOrArenaIsRefused() {
        assertFalse(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.STACK, MemoryRegion.USER));
        assertFalse(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.STACK, MemoryRegion.ARENA));
    }

    @Test
    void stackToKernelTrackedProceeds() {
        assertTrue(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.STACK, MemoryRegion.KERNEL_TRACKED));
    }

    @Test
    void kernelTrackedDegradesToKernelUntracked() {
        assertTrue(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.KERNEL_TRACKED, MemoryRegion.KERNEL_UNTRACKED));
        // But not the other way — passing an untracked pointer where tracked is required is a bug.
        assertFalse(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.KERNEL_UNTRACKED, MemoryRegion.KERNEL_TRACKED));
    }

    @Test
    void userIsolated() {
        // USER → USER: ok.
        assertTrue(PtrCoercionInference.regionAllowsCoercion(MemoryRegion.USER, MemoryRegion.USER));
        // USER → anything else (except UNKNOWN): refused.
        for (var r : MemoryRegion.values()) {
            if (r == MemoryRegion.USER || r == MemoryRegion.UNKNOWN) continue;
            assertFalse(PtrCoercionInference.regionAllowsCoercion(MemoryRegion.USER, r),
                    "USER should not coerce into " + r);
        }
    }

    @Test
    void arenaIsolated() {
        assertTrue(PtrCoercionInference.regionAllowsCoercion(MemoryRegion.ARENA, MemoryRegion.ARENA));
        for (var r : MemoryRegion.values()) {
            if (r == MemoryRegion.ARENA || r == MemoryRegion.UNKNOWN) continue;
            assertFalse(PtrCoercionInference.regionAllowsCoercion(MemoryRegion.ARENA, r));
        }
    }

    @Test
    void mapValueOnlyToKernelTracked() {
        assertTrue(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.MAP_VALUE, MemoryRegion.KERNEL_TRACKED));
        assertFalse(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.MAP_VALUE, MemoryRegion.KERNEL_UNTRACKED));
    }

    @Test
    void packetCoercesIntoKernelTracked() {
        assertTrue(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.PACKET, MemoryRegion.KERNEL_TRACKED));
    }

    @Test
    void unknownExprRefusesNonUnknownParam() {
        // expr=UNKNOWN means we have no provenance — refuse rather than guess.
        assertFalse(PtrCoercionInference.regionAllowsCoercion(
                MemoryRegion.UNKNOWN, MemoryRegion.KERNEL_TRACKED));
    }

    @Test
    void conflictAlwaysRefused() {
        for (var r : MemoryRegion.values()) {
            if (r == MemoryRegion.UNKNOWN) continue;
            assertFalse(PtrCoercionInference.regionAllowsCoercion(MemoryRegion.CONFLICT, r));
        }
    }
}
