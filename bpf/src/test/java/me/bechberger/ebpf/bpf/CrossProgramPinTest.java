package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.BPFProgram.BPFLoadError;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFPerCpuArray;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Layer 1 runtime tests for the pre-load pin-path API on {@link BPFProgram}:
 * {@link BPFProgram#setMapPinPath(String, String)},
 * {@link BPFProgram#getPinPath(String)},
 * {@link BPFProgram#unpin(String)},
 * {@link BPFProgram#unpinAllForClass(Class)},
 * dependent tracking + close-order enforcement, and the
 * {@link BPFProgram#load(Class, BPFProgram...)} overload.
 *
 * <p>Each test program registers its pin paths in {@link BPFProgram#preLoad()},
 * which the generated impl-class constructor calls between {@code super()}
 * and {@code finalizeLoad()}. This is the same seam {@code @SharedFrom} will
 * use; tests here exercise the raw API that {@code @SharedFrom} builds on.
 */
public class CrossProgramPinTest {

    private static final String PIN_DIR  = BPFProgram.BPF_FS_ROOT + "/cross_program_pin_test";
    private static final String PIN_PATH = PIN_DIR + "/counter";

    @BeforeEach
    @AfterEach
    public void cleanup() throws Exception {
        // Ensure no stale pins survive between tests.
        Path dir = Path.of(PIN_DIR);
        if (Files.exists(dir)) {
            try (var stream = Files.walk(dir)) {
                stream.sorted(java.util.Comparator.reverseOrder())
                        .forEach(p -> { try { Files.deleteIfExists(p); } catch (Exception ignore) {} });
            }
        }
    }

    // ── Producer/consumer fixtures ────────────────────────────────────────────

    /**
     * Producer: kprobe on do_sys_openat2 increments a counter and keeps the map
     * pinned at PIN_PATH so a separate program can attach to the same kernel map.
     */
    @BPF(license = "GPL")
    public static abstract class CounterProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = counter.bpf_get(cpu);
            if (v != null) {
                v.set(v.val() + 1);
            } else {
                counter.bpf_put(cpu, 1L);
            }
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", PIN_PATH);
        }
    }

    /**
     * Consumer: same map shape, registered against the same pin path. No probes —
     * we only want to read what the producer wrote.
     */
    @BPF(license = "GPL")
    public static abstract class CounterConsumer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", PIN_PATH);
        }
    }

    /** Schema-mismatched consumer: same name, but value type is int instead of long. */
    @BPF(license = "GPL")
    public static abstract class CounterConsumerWrongValue extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Integer> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) {
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", PIN_PATH);
        }
    }

    /** Producer with a deeper pin path to verify intermediate dirs are auto-created. */
    @BPF(license = "GPL")
    public static abstract class DeepDirProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            counter.bpf_put(cpu, 1L);
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", BPFProgram.BPF_FS_ROOT + "/cross_program_pin_test/a/b/c/counter");
        }
    }

    /** Producer that registers a path outside /sys/fs/bpf — must be rejected eagerly. */
    @BPF(license = "GPL")
    public static abstract class BadPathProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", "/tmp/cross_program_pin_test/counter");
        }
    }

    @Type
    record Event(int pid, int count) {}

    /** Producer with a ring buffer pinned at PIN_PATH. */
    @BPF(license = "GPL")
    public static abstract class RingBufferProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 4096)
        BPFRingBuffer<Event> events;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            Ptr<Event> ev = events.reserve();
            if (ev == null) return 0;
            Ptr.of(ev.val().pid).set(7);
            Ptr.of(ev.val().count).set(1);
            events.submit(ev);
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("events", PIN_DIR + "/events");
        }
    }

    /** Consumer that opens the producer's pinned ring buffer and reads from it. */
    @BPF(license = "GPL")
    public static abstract class RingBufferConsumer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 4096)
        BPFRingBuffer<Event> events;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }

        @Override
        protected void preLoad() {
            setMapPinPath("events", PIN_DIR + "/events");
        }
    }

    /** Producer with a per-CPU array pinned at PIN_PATH. */
    @BPF(license = "GPL")
    public static abstract class PerCpuProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFPerCpuArray<Integer> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            int key = 0;
            Ptr<Integer> v = counter.bpf_get(key);
            if (v != null) {
                BPFJ.sync_fetch_and_add(v, 1);
            }
            return 0;
        }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", PIN_DIR + "/percpu");
        }
    }

    /** Consumer that opens the producer's pinned per-CPU array. */
    @BPF(license = "GPL")
    public static abstract class PerCpuConsumer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 1)
        BPFPerCpuArray<Integer> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = false)
        int neverAttached(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }

        @Override
        protected void preLoad() {
            setMapPinPath("counter", PIN_DIR + "/percpu");
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /** #1 Two programs share a hash map via a registered pin path. */
    @Test
    @Timeout(20)
    public void testTwoProgramsShareSimpleMap() throws Exception {
        try (var producer = BPFProgram.load(CounterProducer.class)) {
            assertEquals(PIN_PATH, producer.getPinPath("counter"),
                    "getPinPath must reflect what setMapPinPath registered");
            assertTrue(producer.getPinnedMapNames().contains("counter"));
            assertTrue(Files.exists(Path.of(PIN_PATH)),
                    "Pin file must exist after load");

            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(CounterConsumer.class)) {
                long total = consumer.counter.keySet().stream()
                        .mapToLong(k -> { Long v = consumer.counter.get(k); return v == null ? 0 : v; })
                        .sum();
                assertTrue(total >= 5,
                        "Consumer should see producer's writes via the pinned map: " + total);
            }
        }
    }

    /** #2 Pin survives producer close — consumer loads later and still reads values. */
    @Test
    @Timeout(20)
    public void testConsumerOutlivesProducer() throws Exception {
        long beforeClose;
        try (var producer = BPFProgram.load(CounterProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            beforeClose = producer.counter.keySet().stream()
                    .mapToLong(k -> { Long v = producer.counter.get(k); return v == null ? 0 : v; })
                    .sum();
            assertTrue(beforeClose >= 5);
        }
        // Producer is closed, but the pin keeps the kernel map alive.
        assertTrue(Files.exists(Path.of(PIN_PATH)),
                "Pin must survive producer close");

        try (var consumer = BPFProgram.load(CounterConsumer.class)) {
            long afterReopen = consumer.counter.keySet().stream()
                    .mapToLong(k -> { Long v = consumer.counter.get(k); return v == null ? 0 : v; })
                    .sum();
            assertTrue(afterReopen >= beforeClose,
                    "Reopened map count " + afterReopen + " >= " + beforeClose);
        }
    }

    /** #3 Two producer instances reusing the same pin path observe each other. */
    @Test
    @Timeout(20)
    public void testProducerLoadedTwiceReusesPin() throws Exception {
        long firstCount;
        try (var producer = BPFProgram.load(CounterProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            firstCount = producer.counter.keySet().stream()
                    .mapToLong(k -> { Long v = producer.counter.get(k); return v == null ? 0 : v; })
                    .sum();
            assertTrue(firstCount >= 5);
        }
        // Second instance with the same class — it should observe the prior writes
        // since libbpf reuses the existing pin (no LIBBPF_PIN_BY_NAME purge here).
        try (var producer2 = BPFProgram.load(CounterProducer.class)) {
            long secondView = producer2.counter.keySet().stream()
                    .mapToLong(k -> { Long v = producer2.counter.get(k); return v == null ? 0 : v; })
                    .sum();
            assertTrue(secondView >= firstCount,
                    "Second producer instance should see prior writes via pin: "
                            + secondView + " >= " + firstCount);
        }
    }

    /** #4 {@code unpin(path)} removes the pin file. */
    @Test
    @Timeout(20)
    public void testPinPathCleanupOnExplicitUnpin() throws Exception {
        try (var producer = BPFProgram.load(CounterProducer.class)) {
            assertTrue(Files.exists(Path.of(PIN_PATH)));
        }
        assertTrue(Files.exists(Path.of(PIN_PATH)),
                "Pin should still exist after producer close (sanity)");
        BPFProgram.unpin(PIN_PATH);
        assertFalse(Files.exists(Path.of(PIN_PATH)),
                "unpin() must delete the file");
        // Idempotent — second call must not throw.
        BPFProgram.unpin(PIN_PATH);
    }

    /** #5 Intermediate pin directories are auto-created. */
    @Test
    @Timeout(20)
    public void testMissingPinDirectoryAutoCreated() throws Exception {
        Path deep = Path.of(BPFProgram.BPF_FS_ROOT + "/cross_program_pin_test/a/b/c/counter");
        try (var producer = BPFProgram.load(DeepDirProducer.class)) {
            assertTrue(Files.exists(deep),
                    "Deep pin path must be auto-created: " + deep);
        }
    }

    /** #6 Schema mismatch on pin reuse surfaces as a clean BPFLoadError. */
    @Test
    @Timeout(20)
    public void testSchemaMismatchProducesCleanError() throws Exception {
        try (var producer = BPFProgram.load(CounterProducer.class)) {
            // pin is now established with value-size = 8 (Long).
            BPFLoadError err = assertThrows(BPFLoadError.class,
                    () -> BPFProgram.load(CounterConsumerWrongValue.class),
                    "Loading a consumer with mismatched value type must fail");
            // Don't assert exact wording — libbpf's message varies — but it
            // should mention either the map name, value, size, or 'pin'.
            String msg = err.getMessage() == null ? "" : err.getMessage().toLowerCase();
            assertTrue(
                    msg.contains("load") || msg.contains("counter")
                            || msg.contains("pin") || msg.contains("size"),
                    "Error should be informative: " + err.getMessage());
        }
    }

    /** #7 A pin path outside /sys/fs/bpf is rejected eagerly with a clear error. */
    @Test
    @Timeout(20)
    public void testInvalidPinPathRejected() {
        BPFError err = assertThrows(BPFError.class,
                () -> BPFProgram.load(BadPathProducer.class),
                "Pin paths outside " + BPFProgram.BPF_FS_ROOT + " must be rejected");
        assertTrue(err.getMessage().contains(BPFProgram.BPF_FS_ROOT),
                "Error must name the required prefix: " + err.getMessage());
    }

    /** #8 Ring buffers can be shared via pin. */
    @Test
    @Timeout(20)
    public void testRingBufferShareableViaPin() throws Exception {
        AtomicReference<Event> received = new AtomicReference<>();
        try (var producer = BPFProgram.load(RingBufferProducer.class);
             var consumer = BPFProgram.load(RingBufferConsumer.class)) {

            // Consumer wires a callback on the *shared* ring buffer.
            consumer.events.setCallback(ev -> received.set(ev));

            producer.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (received.get() == null && System.currentTimeMillis() < deadline) {
                try { consumer.events.consume(); } catch (Exception ignore) {}
                Thread.sleep(20);
            }
            Event ev = received.get();
            assertNotNull(ev, "Consumer must receive an event from the producer's ring buffer");
            assertEquals(7, ev.pid());
            assertEquals(1, ev.count());
        }
    }

    /** #9 Per-CPU arrays can be shared via pin. */
    @Test
    @Timeout(20)
    public void testPerCpuArrayShareableViaPin() throws Exception {
        try (var producer = BPFProgram.load(PerCpuProducer.class)) {
            producer.autoAttachPrograms();
            for (int i = 0; i < 5; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);

            try (var consumer = BPFProgram.load(PerCpuConsumer.class)) {
                long total = consumer.counter.sumAll(0);
                assertTrue(total >= 5,
                        "Consumer should see producer's per-cpu increments: " + total);
            }
        }
    }

    /** #10 The legacy post-load pinning API ({@code MapPinningTest}) still works. */
    @Test
    @Timeout(20)
    public void testLegacyPostLoadPinningStillWorks() throws Exception {
        // Mini-rerun of the existing MapPinningTest pattern: post-load pinning
        // via pinMap()/openPinnedMap() must continue to function alongside the
        // new pre-load setMapPinPath path. A regression here means Layer 1
        // broke the existing API, not just the new one.
        String legacyPin = "/sys/fs/bpf/test_cross_program_legacy_pin";
        Files.deleteIfExists(Path.of(legacyPin));
        try (var program = BPFProgram.load(MapPinningTest.Program.class)) {
            program.autoAttachPrograms();
            for (int i = 0; i < 3; i++) TestUtil.triggerOpenAt();
            Thread.sleep(200);
            program.pinMap("counter", legacyPin);
            assertTrue(Files.exists(Path.of(legacyPin)));
        }
        try (var p2 = BPFProgram.load(MapPinningTest.Program.class)) {
            BPFHashMap<Integer, Long> reopened = p2.openPinnedMap(
                    legacyPin,
                    fd -> new BPFHashMap<>(fd, BPFType.BPFIntType.INT32, BPFType.BPFIntType.INT64));
            long sum = reopened.keySet().stream()
                    .mapToLong(k -> { Long v = reopened.get(k); return v == null ? 0 : v; })
                    .sum();
            assertTrue(sum >= 3, "Legacy post-load pin should still carry counts: " + sum);
        } finally {
            Files.deleteIfExists(Path.of(legacyPin));
        }
    }

    /** Bonus: dependent tracking + close-order enforcement. */
    @Test
    @Timeout(20)
    public void testCloseProducerWhileConsumerAliveThrows() throws Exception {
        // We can't use load(Class, BPFProgram...) here — the consumer has no
        // @SharedFrom and therefore no parameterized constructor. Instead,
        // exercise the dependent-tracking primitives directly via reflection
        // of the package-private addDependent / removeDependent.
        var producer = BPFProgram.load(CounterProducer.class);
        BPFProgram consumer = null;
        try {
            consumer = BPFProgram.load(CounterConsumer.class);
            // Manually register the dependency the way load(Class, producers...) would.
            var addDep = BPFProgram.class.getDeclaredMethod("addDependent", BPFProgram.class);
            addDep.setAccessible(true);
            addDep.invoke(producer, consumer);

            IllegalStateException ex = assertThrows(IllegalStateException.class,
                    producer::close,
                    "Closing producer while consumer is alive must throw");
            assertTrue(ex.getMessage().toLowerCase().contains("consumer")
                            || ex.getMessage().contains("CounterConsumer"),
                    "Message must indicate dependents are alive: " + ex.getMessage());
        } finally {
            if (consumer != null) consumer.close();
            producer.close();
        }
    }

    /**
     * Bonus: {@code unpinAllForClass} wipes the producer's pin directory.
     *
     * <p>We can't write arbitrary files into {@code /sys/fs/bpf} (the BPF
     * filesystem only accepts pin files created by libbpf), so this test uses
     * a real producer to create real pins, then verifies that
     * {@code unpinAllForClass} removes them.
     */
    @Test
    @Timeout(20)
    public void testUnpinAllForClass() throws Exception {
        // CounterProducer pins "counter" under PIN_DIR (= /sys/fs/bpf/cross_program_pin_test).
        // We want to test unpinAllForClass against the *default* dir for the
        // CounterProducer class, so create a custom producer that uses the default path.
        Path defaultDir = Path.of(BPFProgram.defaultPinDir(DefaultPinProducer.class));
        Path defaultFile = Path.of(BPFProgram.defaultPinPath(DefaultPinProducer.class, "counter"));
        // Pre-clean.
        BPFProgram.unpinAllForClass(DefaultPinProducer.class);

        try (var producer = BPFProgram.load(DefaultPinProducer.class)) {
            assertTrue(Files.exists(defaultDir), "Default pin dir must be created: " + defaultDir);
            assertTrue(Files.exists(defaultFile), "Default pin file must exist: " + defaultFile);
        }

        // Pin survives close.
        assertTrue(Files.exists(defaultFile));

        BPFProgram.unpinAllForClass(DefaultPinProducer.class);
        assertFalse(Files.exists(defaultDir),
                "unpinAllForClass must remove the entire pin directory");

        // Idempotent: second call on a missing dir does nothing.
        BPFProgram.unpinAllForClass(DefaultPinProducer.class);
    }

    /** Helper: producer that pins a map at the default class-derived path. */
    @BPF(license = "GPL")
    public static abstract class DefaultPinProducer extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) { return 0; }

        @Override
        protected void preLoad() {
            setMapPinPath("counter",
                    BPFProgram.defaultPinPath(DefaultPinProducer.class, "counter"));
        }
    }
}
