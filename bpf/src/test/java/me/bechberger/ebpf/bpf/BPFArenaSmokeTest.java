package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke test for {@link BPFArena}: loads a program containing an arena map,
 * verifies the kernel reports it as {@link MapTypeId#ARENA}, and that
 * {@code userView()} returns a {@link java.lang.foreign.MemorySegment}
 * sized to the requested page count.
 * <p>
 * This is a load-side test only — it does not yet exercise the in-BPF
 * arena allocation/access path (covered by later Phase F items once
 * {@code @InArena} and the {@code bpf_arena_alloc_pages} BPFJ helpers land).
 */
public class BPFArenaSmokeTest {

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 2)
        BPFArena arena;

        // A trivial kprobe so the program is loadable. We don't touch the
        // arena from BPF yet; this test only verifies map creation.
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
            view.set(java.lang.foreign.ValueLayout.JAVA_INT, 0, 0xCAFEBABE);
            assertEquals(0xCAFEBABE, view.get(java.lang.foreign.ValueLayout.JAVA_INT, 0));
        }
    }
}
