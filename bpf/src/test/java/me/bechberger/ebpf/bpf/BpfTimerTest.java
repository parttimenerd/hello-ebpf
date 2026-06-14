package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for BPF timers.
 *
 * <p>A kprobe on {@code do_sys_openat2} initialises a {@code bpf_timer} stored
 * in a hash map. The timer fires after 100 ms and self-re-arms up to 3 times.
 * Each tick increments the {@code tickCount} global variable. After ~500 ms
 * user-space asserts that at least 2 ticks occurred.
 *
 * <p>This test uses a raw C body in the callback method because the compiler
 * plugin does not yet support method-reference-style timer callbacks — the same
 * pattern as {@link me.bechberger.ebpf.samples.TimerDemo}.
 */
public class BpfTimerTest {

    static final long TICK_NS = 100_000_000L; // 100 ms

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram {

        private static final String EBPF_PROGRAM = """
                #include <vmlinux.h>
                #include <bpf/bpf_helpers.h>

                struct timer_val {
                    struct bpf_timer timer;
                    __u32 initialized;
                };

                struct {
                    __uint(type, BPF_MAP_TYPE_HASH);
                    __type(key, __u32);
                    __type(value, struct timer_val);
                    __uint(max_entries, 1);
                } timer_map SEC(".maps");
                """;

        /** Number of timer ticks so far. */
        final GlobalVariable<@Unsigned Integer> tickCount = new GlobalVariable<>(0);

        /** Maximum number of re-arms before the timer stops. */
        final GlobalVariable<@Unsigned Integer> maxTicks = new GlobalVariable<>(3);

        /**
         * Timer callback: increments tickCount and re-arms for another TICK_NS
         * until maxTicks is reached.
         *
         * <p>Raw C body required because the plugin doesn't yet translate Java
         * method references into {@code bpf_timer_set_callback} function pointers.
         */
        @BPFTimer
        @BPFFunction(inline = false)
        public int timerTick(Ptr<?> map, Ptr<Integer> key, Ptr<?> val) {
            String code = """
                    if (tickCount < maxTicks) {
                        tickCount++;
                        bpf_timer_start(&((struct timer_val *)val)->timer,
                                        100000000ULL, 0);
                    }
                    return 0;
                    """;
            return 0;
        }

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            String code = """
                    __u32 key = 0;
                    struct timer_val *tv = bpf_map_lookup_elem(&timer_map, &key);
                    if (!tv) return 0;
                    if (!tv->initialized) {
                        tv->initialized = 1;
                        bpf_timer_init(&tv->timer, &timer_map, 1 /* CLOCK_MONOTONIC */);
                        bpf_timer_set_callback(&tv->timer, timerTick);
                        bpf_timer_start(&tv->timer, 100000000ULL, 0);
                    }
                    return 0;
                    """;
            return 0;
        }
    }

    @Test
    @Timeout(10)
    @Disabled("kprobe programs cannot use bpf_timer on Linux 6.17 — requires xdp/sk_msg program type")
    public void testTimerFiresAtLeastTwice() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            program.autoAttachPrograms();

            // Pre-insert the timer map entry so the kprobe can find it.
            // (We use raw C initialisation in the kprobe; no Java-side pre-seeding needed.)
            // Arm the timer by triggering the kprobe.
            TestUtil.triggerOpenAt();

            // Wait up to 2 seconds for at least 2 ticks (each 100 ms apart).
            long deadline = System.currentTimeMillis() + 2000;
            while (program.tickCount.get() < 2 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            int ticks = program.tickCount.get();
            assertTrue(ticks >= 2,
                    "Timer should have fired at least 2 times in 2 s, got " + ticks + " ticks");
        }
    }

    @Test
    @Timeout(10)
    @Disabled("kprobe programs cannot use bpf_timer on Linux 6.17 — requires xdp/sk_msg program type")
    public void testTimerRespectsMaXTicks() throws InterruptedException {
        try (var program = BPFProgram.load(Program.class)) {
            // Lower the cap so the timer stops quickly.
            program.maxTicks.set(2);
            program.autoAttachPrograms();

            TestUtil.triggerOpenAt();

            // Wait long enough that the timer would have fired many more times if uncapped.
            Thread.sleep(800);

            int ticks = program.tickCount.get();
            // With a 100 ms interval and cap=2, ticks should be 2 after ~600 ms.
            // Allow ≤3 due to any race between the kprobe arm and test start.
            assertTrue(ticks <= 3,
                    "Timer should have fired at most 3 times with maxTicks=2, got " + ticks);
            assertTrue(ticks >= 2,
                    "Timer should have fired at least 2 times, got " + ticks);
        }
    }
}
