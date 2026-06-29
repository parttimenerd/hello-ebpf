package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.ValueLayout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Smoke tests for {@link BPFArena}.
 *
 * <p>Test ({@code arenaLoadsAndExposesUserView}): verifies the kernel reports the map as
 * {@link MapTypeId#ARENA} and that {@code userView()} returns a correctly-sized
 * {@link java.lang.foreign.MemorySegment}. Includes a user-space write+read round-trip.
 *
 * <p>BPF→Java arena write visibility (the round-trip where BPF writes via a
 * verifier-tracked arena pointer and Java reads it through the mmap) is exercised
 * indirectly via {@link me.bechberger.ebpf.bpf.UserspaceSchedulerBase#setBit}, which
 * runs from the sleepable {@code struct_ops/init} callback (the only context where
 * {@code bpf_arena_alloc_pages} may be called). A standalone kprobe cannot call that
 * kfunc, so no isolated smoke test of BPF arena writes is included here.
 */
public class BPFArenaSmokeTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 2)
        BPFArena arena;

        // A trivial kprobe so the program is loadable.
        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void arenaLoadsAndExposesUserView() {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();
            BPFArena arena = program.arena;
            assertNotNull(arena, "arena map field should be initialised");
            assertEquals(MapTypeId.ARENA, arena.getInfo().type(),
                    "kernel should report this as a BPF_MAP_TYPE_ARENA");
            assertEquals(2, arena.pageCount(), "page count should match @BPFMapDefinition");
            assertEquals(2L * 4096, arena.sizeBytes(), "size should be pageCount * 4096");

            var view = arena.userView();
            assertNotNull(view);
            assertEquals(arena.sizeBytes(), view.byteSize(),
                    "userView segment must span the whole arena");
            // Sanity: can write+read user-side. Even before any BPF write, the
            // kernel zero-initialises arena pages on first fault.
            view.set(ValueLayout.JAVA_INT, 0, 0xCAFEBABE);
            assertEquals(0xCAFEBABE, view.get(ValueLayout.JAVA_INT, 0));
        }
    }

    /**
     * BPF→Java arena write visibility contract.
     *
     * <p>This test would verify that a BPF program can write into the arena via a
     * verifier-tracked pointer obtained from {@code bpf_arena_alloc_pages}, and that
     * the written bytes are visible to Java via {@code userView()} without any syscall.
     *
     * <p>A standalone kprobe cannot call {@code bpf_arena_alloc_pages} (it is only
     * permitted in sleepable contexts such as {@code struct_ops/init}). Exercising
     * this contract therefore requires the full sched_ext scheduler init path, which
     * is wired in {@code UserspaceSchedulerBase.init()}.
     *
     * <p>TODO: this contract is exercised end-to-end by Task 18
     * (RustlandFifoSampleSmokeTest); enable when sched_ext kernel testing is wired up.
     */
    @Disabled("requires sched_ext kernel — covered in Task 18 (RustlandFifoSampleSmokeTest)")
    @Test
    @Timeout(10)
    public void bpfToJavaArenaWriteIsVisible() {
        // Placeholder — implementation in Task 18.
    }
}
