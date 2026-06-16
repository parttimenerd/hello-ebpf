package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for BPF timers using the Java DSL (@BPFTimer + method refs).
 *
 * <p>bpf_timer requires an XDP / network / sk_msg / struct_ops program type on
 * Linux 6.17 — kprobe cannot host it.  Both tests attach to loopback (ifindex 1)
 * and arm the timer on the first incoming packet.
 */
public class BpfTimerTest {

    static final long TICK_NS = 100_000_000L; // 100 ms

    // -----------------------------------------------------------------------
    // Shared program type
    // -----------------------------------------------------------------------

    @BPF(license = "GPL")
    public static abstract class Program extends BPFProgram implements XDPHook {

        @Type
        public static class TimerVal {
            public bpf_timer timer;
            public @Unsigned int initialized;
        }

        @BPFMapDefinition(maxEntries = 1)
        BPFHashMap<@Unsigned Integer, TimerVal> timerMap;

        final GlobalVariable<@Unsigned Integer> tickCount = new GlobalVariable<>(0);
        final GlobalVariable<@Unsigned Integer> maxTicks  = new GlobalVariable<>(10);

        /**
         * Re-arms itself every TICK_NS as long as tickCount < maxTicks.
         * Must be {@code static} (BPF verifier requirement for timer callbacks).
         */
        @BPFTimer
        @BPFFunction
        public int timerTick(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
            if (tickCount.get() < maxTicks.get()) {
                tickCount.set(tickCount.get() + 1);
                bpf_timer_start(Ptr.of(val.val().timer), TICK_NS, 0);
            }
            return 0;
        }

        @Override
        public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
            int key = 0;
            Ptr<TimerVal> val = timerMap.bpf_get(key);
            if (val == null) {
                return xdp_action.XDP_PASS;
            }
            if (val.val().initialized == 0) {
                val.val().initialized = 1;
                bpf_timer_init(Ptr.of(val.val().timer), Ptr.of(timerMap), 1 /* CLOCK_MONOTONIC */);
                BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::timerTick);
                bpf_timer_start(Ptr.of(val.val().timer), TICK_NS, 0);
            }
            return xdp_action.XDP_PASS;
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** Pre-seed map, attach to lo, fire one ping to arm the timer. */
    private static Program setupAndArm(int maxTicks) throws Exception {
        Program program = BPFProgram.load(Program.class);
        program.maxTicks.set(maxTicks);
        Program.TimerVal initial = new Program.TimerVal();
        initial.timer = BPFJ.newZeroedTimer();
        program.timerMap.put(0, initial);
        program.xdpAttach(1);
        new ProcessBuilder("ping", "-c", "2", "-W", "1", "127.0.0.1")
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .start()
                .waitFor();
        return program;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    @Test
    @Timeout(15)
    public void testTimerFiresAtLeastTwice() throws Exception {
        try (Program program = setupAndArm(10)) {
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
    @Timeout(15)
    public void testTimerRespectsMaXTicks() throws Exception {
        try (Program program = setupAndArm(2)) {
            // Wait long enough that an uncapped timer would fire many more times.
            Thread.sleep(800);

            int ticks = program.tickCount.get();
            // With a 100 ms interval and cap=2, expect exactly 2 ticks.
            assertTrue(ticks <= 3,
                    "Timer should stop after maxTicks=2, got " + ticks);
            assertTrue(ticks >= 1,
                    "Timer should have fired at least once, got " + ticks);
        }
    }
}
