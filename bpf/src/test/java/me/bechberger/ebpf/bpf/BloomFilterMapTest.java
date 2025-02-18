package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.BPFBloomFilter;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class BloomFilterMapTest {

    public static final int PLACED = 12;

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {
        @Type
        protected enum ResultPoint implements Enum<ResultPoint> {
            PLACED, BEFORE, AFTER
        }

        @Type
        protected record Result(
                ResultPoint point,
                boolean ok
        ) {
        }

        @BPFMapDefinition(maxEntries = 4)
        BPFRingBuffer<Result> results;

        @BPFMapDefinition(maxEntries = 256)
        BPFBloomFilter<Integer> filter;


        @BPFFunction(
                section = "kprobe/do_sys_openat2",
                autoAttach = true
        )
        int testFilter(Ptr<PtDefinitions.pt_regs> ctx) {
            int placedValue = PLACED;
            Ptr<Result> result = results.reserve();
            if (result != null) {
                Ptr.of(result.val().point).set(ResultPoint.PLACED);
                Ptr.of(result.val().ok).set(filter.peek(placedValue));
                results.submit(result);
            }

            int value;
            for (value = 0; value < 10; value++) {
                int tmp_value = value;
                if (!filter.peek(tmp_value)) {
                    break;
                }
            }

            result = results.reserve();
            if (result != null) {
                Ptr.of(result.val().point).set(ResultPoint.BEFORE);
                Ptr.of(result.val().ok).set(!filter.peek(value));
                results.submit(result);
            }

            filter.put(value);

            result = results.reserve();
            if (result != null) {
                Ptr.of(result.val().point).set(ResultPoint.AFTER);
                Ptr.of(result.val().ok).set(filter.peek(value));
                results.submit(result);
            }

            return 0;
        }
    }

    @Test
    public void testBasicBloomFilter() {
        try (var program = BPFProgram.load(BloomFilterMapTest.Program.class)) {
            program.autoAttachPrograms();
            var filter = program.filter;
            filter.put(PLACED);
            TestUtil.triggerOpenAt();

            List<Program.Result> results = new ArrayList<>();

            program.results.setCallback(result -> {
                results.add(result);
            });

            while (results.size() < 3) {
                program.results.consumeAndThrow();
            }

            for (var result : results) {
                assertTrue(result.ok, result.toString());
            }
        }
        TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
    }
}
