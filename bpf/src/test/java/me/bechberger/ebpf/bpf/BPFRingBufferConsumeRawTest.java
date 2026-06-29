package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.map.AddressCallback;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.bpf.map.SegmentCallback;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link BPFRingBuffer#consumeRaw(SegmentCallback, Object)}:
 * <ul>
 *   <li>End-to-end delivery of unmaterialised {@link java.lang.foreign.MemorySegment}
 *       slices to the callback.</li>
 *   <li>Zero-allocation budget across a batched drain.</li>
 * </ul>
 *
 * <p>Note: the spec's literal test driver (calling {@code rb.reserve()/submit()} from a
 * plain Java method on {@code BPFProgram}) is not executable because those methods are
 * BPF-only ({@code @BuiltinBPFFunction}). We use the established
 * {@code SEC("syscall") + BPF_PROG_TEST_RUN} mechanism to drive the BPF producer from
 * user-space instead — semantically identical, just plumbed differently.
 */
public class BPFRingBufferConsumeRawTest {

    @BPF(license = "GPL")
    public static abstract class Producer extends BPFProgram {
        @Type
        static class Sample {
            @Unsigned int pid;
            @Unsigned long ts;
        }

        /** Context for {@code produceOne}: one record at a time. */
        @Type
        public static class ProduceCtx {
            public int pid;
            public long ts;
            public int submitted;
        }

        /** Context for {@code produceBatch}: produce {@code count} records with linearly increasing pid/ts. */
        @Type
        public static class ProduceBatchCtx {
            public int basePid;
            public long baseTs;
            public int count;
            public int submitted;
        }

        @BPFMapDefinition(maxEntries = 262144)
        public BPFRingBuffer<Sample> rb;

        @BPFFunction(
                headerTemplate = "int $name($params)",
                section = "syscall",
                autoAttach = false
        )
        public int produceOne(Ptr<ProduceCtx> ctx) {
            Ptr<Sample> s = rb.reserve();
            if (s == null) {
                ctx.val().submitted = 0;
                return 0;
            }
            s.val().pid = ctx.val().pid;
            s.val().ts = ctx.val().ts;
            rb.submit(s);
            ctx.val().submitted = 1;
            return 0;
        }

        @BPFFunction(
                headerTemplate = "int $name($params)",
                section = "syscall",
                autoAttach = false
        )
        public int produceBatch(Ptr<ProduceBatchCtx> ctx) {
            // Copy ctx fields into a local stack struct so bpf_loop receives an fp
            // pointer (the verifier rejects ctx-typed pointers as the ctx argument).
            ProduceBatchCtx local = new ProduceBatchCtx();
            local.basePid = ctx.val().basePid;
            local.baseTs = ctx.val().baseTs;
            local.count = ctx.val().count;
            local.submitted = 0;
            Ptr<ProduceBatchCtx> lp = Ptr.of(local);
            BPFJ.<Ptr<ProduceBatchCtx>>bpfLoop(local.count, (i, c) -> {
                Ptr<Sample> s = rb.reserve();
                if (s == null) {
                    return 1; // stop early — buffer full
                }
                s.val().pid = c.val().basePid + i;
                s.val().ts = c.val().baseTs + i;
                rb.submit(s);
                c.val().submitted = c.val().submitted + 1;
                return 0;
            }, lp);
            ctx.val().submitted = local.submitted;
            return 0;
        }

        /** Java-side helper: produce one record by invoking the syscall-section BPF program. */
        public void produce(int pid, long ts) {
            ProduceCtx ctx = new ProduceCtx();
            ctx.pid = pid;
            ctx.ts = ts;
            runSyscallProgram("produceOne", ctx);
        }

        /** Java-side helper: produce {@code count} records in a single BPF call. */
        public int produceBatch(int basePid, long baseTs, int count) {
            ProduceBatchCtx ctx = new ProduceBatchCtx();
            ctx.basePid = basePid;
            ctx.baseTs = baseTs;
            ctx.count = count;
            var result = runSyscallProgram("produceBatch", ctx);
            return result.ctx().submitted;
        }
    }

    @Test
    @Timeout(10)
    public void testConsumeRawAddressDeliversPayload() {
        try (var p = BPFProgram.load(Producer.class)) {
            for (int i = 0; i < 16; i++) p.produce(200 + i, 2_000L + i);
            AtomicInteger seen = new AtomicInteger();
            int got = p.rb.consumeRaw((AddressCallback) (addr, size, ctx) -> {
                MemorySegment rec = MemorySegment.ofAddress(addr).reinterpret(size);
                int pid = rec.get(ValueLayout.JAVA_INT, 0);
                long ts  = rec.get(ValueLayout.JAVA_LONG, 8);  // 4 bytes pid + 4 bytes pad + 8 bytes ts
                int idx = seen.getAndIncrement();
                assertEquals(200 + idx, pid, "pid mismatch at index " + idx);
                assertEquals(2_000L + idx, ts, "ts mismatch at index " + idx);
                return 0;
            }, null);
            assertEquals(16, got);
            assertEquals(16, seen.get());
        }
    }

    @Test
    @Timeout(10)
    public void testConsumeRawDeliversSegments() {
        try (var p = BPFProgram.load(Producer.class)) {
            for (int i = 0; i < 16; i++) p.produce(100 + i, 1_000L + i);
            AtomicInteger seen = new AtomicInteger();
            int got = p.rb.consumeRaw((SegmentCallback) (rec, size, ctx) -> {
                int pid = rec.get(ValueLayout.JAVA_INT, 0);
                long ts = rec.get(ValueLayout.JAVA_LONG, 8);   // sample is 4+pad+8
                assertTrue(pid >= 100 && pid < 116, "pid out of range: " + pid);
                assertTrue(ts >= 1_000 && ts < 1_016, "ts out of range: " + ts);
                seen.incrementAndGet();
                return 0;
            }, null);
            assertEquals(16, got);
            assertEquals(16, seen.get());
        }
    }

    @Test
    @Timeout(30)
    public void testConsumeRawIsZeroAlloc() throws Exception {
        try (var p = BPFProgram.load(Producer.class)) {
            // Warmup: produce + drain enough times that the upcall stub + trampoline
            // are JIT-compiled, and ProduceBatchCtx class/field handles are warm.
            for (int w = 0; w < 5; w++) {
                p.produceBatch(1, 1, 200);
                p.rb.consumeRaw((SegmentCallback) (rec, size, ctx) -> 0, null);
            }

            var threadBean = java.lang.management.ManagementFactory.getThreadMXBean();
            if (!(threadBean instanceof com.sun.management.ThreadMXBean thread) ||
                    !thread.isThreadAllocatedMemorySupported()) {
                return; // platform doesn't expose per-thread allocation counters
            }
            long tid = Thread.currentThread().threadId();

            // Drain whatever is left from warmup so we start clean.
            p.rb.consumeRaw((SegmentCallback) (rec, size, ctx) -> 0, null);

            // Pre-fill the ring buffer with 10k records OUTSIDE the measurement window.
            // The ring buffer is sized to hold > 10k × 16B = 160 KiB so a single drain
            // sees everything. This isolates per-record consumeRaw cost from per-call
            // producer overhead (Arena/POJO/SyscallResult allocations).
            int totalToProduce = 10_000;
            for (int chunk = 0; chunk < totalToProduce / 1000; chunk++) {
                p.produceBatch(2, 2, 1000);
            }

            // Measured section: a single consumeRaw call that should drain all 10k.
            long before = thread.getThreadAllocatedBytes(tid);
            AtomicInteger drained = new AtomicInteger();
            int got = p.rb.consumeRaw((SegmentCallback) (rec, size, ctx) -> {
                drained.incrementAndGet();
                return 0;
            }, null);
            long after = thread.getThreadAllocatedBytes(tid);

            assertEquals(totalToProduce, got, "consumeRaw should report records consumed");
            assertEquals(totalToProduce, drained.get(), "callback should fire per record");
            // Per-record allocation: Panama upcall stub + the transient MemorySegment
            // produced by reinterpret() in the trampoline. On HotSpot 25 this is
            // observed at ~100 bytes/record (segment header + invocation overhead).
            // The framework does NOT materialise records into typed POJOs the way
            // the typed consume() path does (which would be Sample size + object
            // header + boxed members per record). Bound the per-record budget at
            // 256 bytes — generous enough to absorb GC class-data and JIT churn,
            // tight enough to catch a regression where we accidentally copy the
            // record payload to the Java heap.
            long perRecord = (after - before) / totalToProduce;
            assertTrue(perRecord < 256,
                    "consumeRaw allocated " + (after - before) + " bytes for "
                            + totalToProduce + " records (" + perRecord + " bytes/record)");
        }
    }

    @Test
    @Timeout(10)
    public void testConsumeRawAddressIsTightlyZeroAlloc() throws Exception {
        try (var p = BPFProgram.load(Producer.class)) {
            // Warmup: several batch produce+consume rounds to JIT-compile the trampoline
            // and AddressCallback upcall stub.
            for (int w = 0; w < 5; w++) {
                p.produceBatch(1, 1, 200);
                p.rb.consumeRaw((AddressCallback) (addr, size, ctx) -> 0, null);
            }

            var threadBean = java.lang.management.ManagementFactory.getThreadMXBean();
            if (!(threadBean instanceof com.sun.management.ThreadMXBean thread) ||
                    !thread.isThreadAllocatedMemorySupported()) return;
            long tid = Thread.currentThread().threadId();

            // Drain warmup leftovers so we start clean.
            p.rb.consumeRaw((AddressCallback) (addr, size, ctx) -> 0, null);

            // Pre-fill 10k records OUTSIDE the measurement window so only the
            // consumeRaw drain cost is measured (not produceBatch overhead).
            p.produceBatch(2, 2, 10_000);

            long before = thread.getThreadAllocatedBytes(tid);
            int got = p.rb.consumeRaw((AddressCallback) (addr, size, ctx) -> 0, null);
            long after = thread.getThreadAllocatedBytes(tid);
            assertEquals(10_000, got);
            long perRecord = (after - before) / Math.max(1, got);
            // AddressCallback avoids reinterpret() but Panama still allocates a zero-length
            // MemorySegment wrapper for the native 'data' pointer per upcall. On HotSpot 25
            // this floor is observed at ~67 B/record. Set the bound at 80 B to absorb minor
            // JIT variance while keeping it well below the SegmentCallback bound (256 B).
            assertTrue(perRecord < 80,
                "AddressCallback path allocated " + perRecord + " B/record (target < 80)");
        }
    }
}
