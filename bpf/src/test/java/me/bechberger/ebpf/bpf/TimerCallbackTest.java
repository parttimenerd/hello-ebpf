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
 * Item 6 verification: a timer callback specified via Java method-reference on an
 * XDP program. The XDP program is attached to the loopback interface and triggered
 * by sending traffic to localhost; on the first packet, Java arms a 50 ms self-rearming
 * timer, and we read the tick count from a {@link GlobalVariable}.
 *
 * <p>This is the smallest end-to-end exerciser of {@link BPFJ#bpf_timer_set_callback}
 * — no raw C, no lambdas, just a method reference to a {@code @BPFFunction}.
 *
 * <p>kprobe / SEC("syscall") cannot host a {@code bpf_timer} on Linux 6.17 — the
 * helper is restricted to network/sk_msg/struct_ops/cgroup program types. XDP is
 * the path that compiles and loads.
 */
public class TimerCallbackTest {

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

        /** Re-arms itself for another 50 ms tick. */
        @BPFTimer
        @BPFFunction
        public int onTick(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
            tickCount.set(tickCount.get() + 1);
            bpf_timer_start(Ptr.of(val.val().timer), 50_000_000L, 0);
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
                BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::onTick);
                bpf_timer_start(Ptr.of(val.val().timer), 50_000_000L, 0);
            }
            return xdp_action.XDP_PASS;
        }
    }

    @Test
    @Timeout(15)
    public void testTimerCallbackFires() throws Exception {
        try (var program = BPFProgram.load(Program.class)) {
            // Pre-seed the map with an empty entry so the XDP program can find it.
            // BPFJ.newZeroedTimer() handles the bpf_timer slot allocation.
            Program.TimerVal initial = new Program.TimerVal();
            initial.timer = BPFJ.newZeroedTimer();
            program.timerMap.put(0, initial);

            // Attach to loopback (ifindex 1 in any sane VM).
            program.xdpAttach(1);

            // Trigger the XDP hook by sending traffic on lo. ping is universally available.
            Process p = new ProcessBuilder("ping", "-c", "2", "-W", "1", "127.0.0.1")
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start();
            p.waitFor();

            // Wait for several ticks (50ms each).
            long deadline = System.currentTimeMillis() + 4000;
            while (program.tickCount.get() < 3 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            int ticks = program.tickCount.get();
            assertTrue(ticks >= 3, "Expected ≥3 ticks in 4s, got " + ticks);
        }
    }
}
