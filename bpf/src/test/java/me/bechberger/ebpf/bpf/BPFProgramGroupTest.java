package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.annotations.bpf.SharedFrom;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BPFProgramGroup}.
 */
public class BPFProgramGroupTest {

    @BPF(license = "GPL")
    public static abstract class GroupProducer extends BPFProgram {
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> shared;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = shared.bpf_get(cpu);
            if (v != null) v.set(v.val() + 1);
            else shared.bpf_put(cpu, 1L);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class GroupConsumer extends BPFProgram {
        @SharedFrom(GroupProducer.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> shared;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @BeforeEach
    @AfterEach
    public void cleanup() {
        BPFProgram.unpinAllForClass(GroupProducer.class);
    }

    @Test
    @Timeout(20)
    public void closesInReverseDependencyOrder() throws Exception {
        var producer = BPFProgram.load(GroupProducer.class);
        var consumer = BPFProgram.load(GroupConsumer.class, producer);

        // Without the group, closing producer first throws because consumer is a dependent.
        // The group must close consumer first so producer can close cleanly.
        try (var grp = BPFProgramGroup.of(producer, consumer)) {
            assertEquals(2, grp.members().size());
        }
        // After group close both should be unusable; calling close again is a no-op.
        producer.close();
        consumer.close();
    }

    @Test
    @Timeout(20)
    public void andAttachRunsAttachStep() throws Exception {
        AtomicInteger count = new AtomicInteger();
        try (var producer = BPFProgram.load(GroupProducer.class);
             var consumer = BPFProgram.load(GroupConsumer.class, producer)) {

            var grp = BPFProgramGroup.of(producer, consumer)
                    .andAttach(count::incrementAndGet)
                    .andAttach(count::incrementAndGet);
            assertEquals(2, count.get());
            // close manually since we held the programs in try-with-resources
            // (group close would also work, but here we test only attach + members)
            assertEquals(2, grp.members().size());
        }
    }

    @Test
    @Timeout(20)
    public void runUntilInterruptedHonoursTimeout() throws Exception {
        try (var producer = BPFProgram.load(GroupProducer.class);
             var consumer = BPFProgram.load(GroupConsumer.class, producer);
             var grp = BPFProgramGroup.of(producer, consumer)) {
            long t0 = System.nanoTime();
            grp.runUntilInterrupted(Duration.ofMillis(200), Duration.ofMillis(50));
            long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
            assertTrue(elapsedMs >= 150 && elapsedMs < 5_000,
                    "runUntilInterrupted should respect ~200ms timeout, elapsed=" + elapsedMs);
        }
    }

    @Test
    public void rejectsNullPrograms() {
        assertThrows(IllegalArgumentException.class, () -> BPFProgramGroup.of(null));
    }
}
