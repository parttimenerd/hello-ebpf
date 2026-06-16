package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for BPF map pinning ({@code pinMap} / {@code openPinnedMap}).
 *
 * <p>Starts a program that increments a counter on every {@code do_sys_openat2},
 * pins the map, closes the program, re-opens the map from the pin path, and
 * verifies the counter survived.
 */
public class MapPinningTest {

    private static final String PIN_PATH = "/sys/fs/bpf/test_map_pinning_counter";

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFHashMap<Integer, Long> counter;

        @BPFFunction(section = "kprobe/do_sys_openat2", autoAttach = true)
        int probe(Ptr<PtDefinitions.pt_regs> ctx) {
            int cpu = BPFJ.currentCpuId();
            Ptr<Long> v = counter.bpf_get(cpu);
            if (v != null) {
                v.set(v.val() + 1);
            } else {
                counter.bpf_put(cpu, 1L);
            }
            return 0;
        }
    }

    @Test
    @Timeout(20)
    public void testMapPinAndReopen() throws Exception {
        // Clean up any stale pin from a previous run
        Files.deleteIfExists(Path.of(PIN_PATH));

        long countBeforeClose;

        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();

            for (int i = 0; i < 5; i++) {
                TestUtil.triggerOpenAt();
            }
            Thread.sleep(200);

            // Pin the map
            program.pinMap("counter", PIN_PATH);
            assertTrue(Files.exists(Path.of(PIN_PATH)), "Pin path must exist after pinMap()");

            countBeforeClose = program.counter.keySet().stream()
                    .mapToLong(k -> { Long v = program.counter.get(k); return v != null ? v : 0; })
                    .sum();
            assertTrue(countBeforeClose >= 5,
                    "Expected at least 5 increments before close, got " + countBeforeClose);
        }
        // Program is closed — the map now only lives via the pin

        // Re-open the pinned map in a fresh program (no probes attached)
        try (var program2 = BPFProgram.load(Program.class)) {
            // deliberately NOT calling autoAttachPrograms() — we only want to read the pin
            BPFHashMap<Integer, Long> reopened = program2.openPinnedMap(
                    PIN_PATH,
                    fd -> new BPFHashMap<>(fd, BPFType.BPFIntType.INT32, BPFType.BPFIntType.INT64));

            long countAfterReopen = reopened.keySet().stream()
                    .mapToLong(k -> { Long v = reopened.get(k); return v != null ? v : 0; })
                    .sum();

            // countAfterReopen may be >= countBeforeClose: events between the count snapshot and
            // program1 close are captured in the pin but not in countBeforeClose.
            assertTrue(countAfterReopen >= countBeforeClose,
                    "Reopened count (" + countAfterReopen + ") must be >= count before close (" + countBeforeClose + ")");
            // Sanity: the pin can't fabricate entries — it should not exceed 2x countBeforeClose.
            assertTrue(countAfterReopen <= countBeforeClose * 2 + 10,
                    "Reopened count (" + countAfterReopen + ") seems unexpectedly large vs " + countBeforeClose);
        } finally {
            Files.deleteIfExists(Path.of(PIN_PATH));
        }
    }
}
