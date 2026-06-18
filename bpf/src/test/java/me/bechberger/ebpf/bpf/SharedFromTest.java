package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
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

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Layer 2 runtime tests for the {@code @SharedFrom} annotation.
 *
 * <p>Each test loads a producer first, then a consumer that imports one or
 * more of the producer's maps via {@code @SharedFrom}. The kernel-side maps
 * are wired up through libbpf pin reuse: the producer pins each shared map
 * under {@code /sys/fs/bpf/<producer-fqn>/<mapName>}; the consumer's
 * generated impl-class {@code preLoad()} registers the same pin path before
 * {@code bpf_object__load}, so both ELFs see the same kernel map.
 */
public class SharedFromTest {

    @BeforeEach
    @AfterEach
    public void cleanup() {
        // Wipe any stale producer pin dirs from earlier failed runs of these tests.
        for (var cls : new Class<?>[]{
                SimpleProducer.class,
                InnerTypeProducer.class,
                NestedTypeProducer.class,
                TwoMapsProducer.class,
                ProducerA.class,
                ProducerB.class}) {
            @SuppressWarnings("unchecked")
            var bpfClass = (Class<? extends BPFProgram>) cls;
            BPFProgram.unpinAllForClass(bpfClass);
        }
    }

    // ── #11 testSharedFromBasicHashMap ────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class SimpleProducer extends BPFProgram {
        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = counter.bpf_get(cpu);
            if (v != null) v.set(v.val() + 1);
            else counter.bpf_put(cpu, 1L);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class SimpleConsumer extends BPFProgram {
        @SharedFrom(SimpleProducer.class)
        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @Test
    @Timeout(20)
    public void testSharedFromBasicHashMap() throws Exception {
        try (var producer = BPFProgram.load(SimpleProducer.class)) {
            // Producer pinned the map at the default path under its FQN dir.
            String pin = BPFProgram.defaultPinPath(SimpleProducer.class, "counter");
            assertTrue(Files.exists(Path.of(pin)), "Producer must pin shared map: " + pin);
            assertEquals(pin, producer.getPinPath("counter"));

            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(SimpleConsumer.class, producer)) {
                // Consumer must be able to read producer's writes.
                long total = consumer.counter.keySet().stream()
                        .mapToLong(k -> {
                            Long v = consumer.counter.get(k);
                            return v == null ? 0 : v;
                        })
                        .sum();
                assertTrue(total >= 5, "Consumer should observe producer's writes: " + total);
            }
        }
    }

    // ── #12 testSharedFromInnerType ──────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class InnerTypeProducer extends BPFProgram {
        @Type
        public static class Stats {
            @Unsigned int hits;
            @Unsigned long lastNs;
        }

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Stats> stats;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Stats> existing = stats.bpf_get(cpu);
            if (existing != null) {
                existing.val().hits++;
            } else {
                Stats s = new Stats();
                s.hits = 1;
                s.lastNs = 0;
                stats.bpf_put(cpu, s);
            }
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class InnerTypeConsumer extends BPFProgram {
        // Reference the producer's @Type directly — the recommended idiomatic path.
        @SharedFrom(InnerTypeProducer.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, InnerTypeProducer.Stats> stats;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @Test
    @Timeout(20)
    public void testSharedFromInnerType() throws Exception {
        try (var producer = BPFProgram.load(InnerTypeProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(InnerTypeConsumer.class, producer)) {
                int seen = 0;
                for (var k : consumer.stats.keySet()) {
                    var v = consumer.stats.get(k);
                    if (v != null && v.hits > 0) seen++;
                }
                assertTrue(seen > 0, "Consumer must read at least one Stats entry produced by the producer");
            }
        }
    }

    // ── #13 testSharedFromComplexNestedType ──────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class NestedTypeProducer extends BPFProgram {
        @Type
        public static class Inner {
            @Unsigned long ts;
            @Unsigned int cpu;
        }
        @Type
        public static class Outer {
            Inner first;
            Inner last;
            @Unsigned long count;
        }

        @BPFMapDefinition(maxEntries = 4)
        BPFHashMap<Integer, Outer> view;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = 0;
            Ptr<Outer> existing = view.bpf_get(key);
            if (existing != null) {
                existing.val().count++;
                existing.val().last.cpu = BPFJ.currentCpuId();
            } else {
                Outer o = new Outer();
                o.count = 1;
                o.first.cpu = BPFJ.currentCpuId();
                o.last.cpu = BPFJ.currentCpuId();
                view.bpf_put(key, o);
            }
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class NestedTypeConsumer extends BPFProgram {
        @SharedFrom(NestedTypeProducer.class)
        @BPFMapDefinition(maxEntries = 4)
        BPFHashMap<Integer, NestedTypeProducer.Outer> view;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @Test
    @Timeout(20)
    public void testSharedFromComplexNestedType() throws Exception {
        try (var producer = BPFProgram.load(NestedTypeProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(NestedTypeConsumer.class, producer)) {
                var entry = consumer.view.get(0);
                assertNotNull(entry, "Consumer must read the Outer entry the producer wrote");
                assertTrue(entry.count >= 1, "count must reflect producer increments");
            }
        }
    }

    // ── #14 testSharedFromTwoMapsFromSameProducer ────────────────────────────

    @BPF(license = "GPL")
    public static abstract class TwoMapsProducer extends BPFProgram {
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> a;

        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> b;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> va = a.bpf_get(cpu);
            if (va != null) va.set(va.val() + 1);
            else a.bpf_put(cpu, 1L);
            Ptr<Long> vb = b.bpf_get(cpu);
            if (vb != null) vb.set(vb.val() + 2);
            else b.bpf_put(cpu, 2L);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class TwoMapsConsumer extends BPFProgram {
        @SharedFrom(TwoMapsProducer.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> a;

        @SharedFrom(TwoMapsProducer.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> b;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @Test
    @Timeout(20)
    public void testSharedFromTwoMapsFromSameProducer() throws Exception {
        try (var producer = BPFProgram.load(TwoMapsProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            // The consumer's generated constructor must take exactly ONE producer
            // (not two), because both @SharedFrom annotations name the same class:
            // load(Class, BPFProgram...) picks a constructor by parameter count.
            try (var consumer = BPFProgram.load(TwoMapsConsumer.class, producer)) {
                long sa = consumer.a.keySet().stream().mapToLong(k -> { Long v = consumer.a.get(k); return v == null ? 0 : v; }).sum();
                long sb = consumer.b.keySet().stream().mapToLong(k -> { Long v = consumer.b.get(k); return v == null ? 0 : v; }).sum();
                assertTrue(sa >= 5, "consumer.a should see producer's writes: " + sa);
                assertTrue(sb >= 10, "consumer.b should see producer's writes: " + sb);
            }
        }
    }

    // ── #15 testSharedFromMapsFromTwoProducers ───────────────────────────────

    @BPF(license = "GPL")
    public static abstract class ProducerA extends BPFProgram {
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> mapA;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = mapA.bpf_get(cpu);
            if (v != null) v.set(v.val() + 1);
            else mapA.bpf_put(cpu, 1L);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class ProducerB extends BPFProgram {
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> mapB;

        @Kprobe("do_sys_openat2")
        int onOpenB(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = mapB.bpf_get(cpu);
            if (v != null) v.set(v.val() + 7);
            else mapB.bpf_put(cpu, 7L);
            return 0;
        }
    }

    @BPF(license = "GPL")
    public static abstract class TwoProducerConsumer extends BPFProgram {
        @SharedFrom(ProducerA.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> mapA;

        @SharedFrom(ProducerB.class)
        @BPFMapDefinition(maxEntries = 8)
        BPFHashMap<Integer, Long> mapB;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }
    }

    @Test
    @Timeout(20)
    public void testSharedFromMapsFromTwoProducers() throws Exception {
        try (var pa = BPFProgram.load(ProducerA.class);
             var pb = BPFProgram.load(ProducerB.class)) {
            pa.autoAttachPrograms();
            pb.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(TwoProducerConsumer.class, pa, pb)) {
                long sa = consumer.mapA.keySet().stream().mapToLong(k -> { Long v = consumer.mapA.get(k); return v == null ? 0 : v; }).sum();
                long sb = consumer.mapB.keySet().stream().mapToLong(k -> { Long v = consumer.mapB.get(k); return v == null ? 0 : v; }).sum();
                assertTrue(sa >= 5, "consumer.mapA should see producerA's writes: " + sa);
                assertTrue(sb >= 35, "consumer.mapB should see producerB's writes (7×5): " + sb);
            }
        }
    }

    // ── #20 testSharedFromCloseConsumerDoesNotUnpin ──────────────────────────

    @Test
    @Timeout(20)
    public void testSharedFromCloseConsumerDoesNotUnpin() throws Exception {
        try (var producer = BPFProgram.load(SimpleProducer.class)) {
            producer.autoAttachPrograms();
            String pin = BPFProgram.defaultPinPath(SimpleProducer.class, "counter");

            // Open and close a consumer.
            try (var consumer = BPFProgram.load(SimpleConsumer.class, producer)) {
                assertTrue(Files.exists(Path.of(pin)));
            }
            // Pin must still exist — consumer close does not own the pin.
            assertTrue(Files.exists(Path.of(pin)),
                    "Consumer.close() must not remove the producer's pin: " + pin);

            // Producer still works after consumer is gone.
            for (int i = 0; i < 3; i++) TestUtil.triggerOpenAt();
            Thread.sleep(150);
        }
    }
}
