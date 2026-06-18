package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_init;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_timer_start;

/**
 * Demonstrates BPF timers in pure Java: a 1-second self-rearming kernel-side timer.
 *
 * <p>On the first incoming packet the XDP hook initializes a {@code bpf_timer}
 * stored in a hash map. The timer fires every second, incrementing
 * {@code tickCount}. The current tick count is printed from Java.
 *
 * <p>The callback is passed as a Java method reference ({@code this::timerCallback});
 * the compiler plugin lowers it to the bare C identifier expected by
 * {@code bpf_timer_set_callback}.
 *
 * <p>Usage (requires root):
 * <pre>
 *   sudo ./run.sh TimerDemo
 * </pre>
 */
@BPF(license = "GPL")
public abstract class TimerDemo extends BPFProgram implements XDPHook {

    /** Map value: a {@code bpf_timer} plus a one-shot init flag. */
    @Type
    static class TimerVal {
        bpf_timer timer;
        @Unsigned int initialized;
    }

    @BPFMapDefinition(maxEntries = 1)
    BPFHashMap<@Unsigned Integer, TimerVal> timerMap;

    /** Tick counter — incremented by the timer callback every second. */
    final GlobalVariable<@Unsigned Integer> tickCount = new GlobalVariable<>(0);

    /** Re-arms the timer for another 1 s. */
    @BPFTimer
    @BPFFunction
    public int timerCallback(Ptr<?> map, Ptr<Integer> key, Ptr<TimerVal> val) {
        tickCount.set(tickCount.get() + 1);
        bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
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
            BPFJ.bpf_timer_set_callback(Ptr.of(val.val().timer), this::timerCallback);
            bpf_timer_start(Ptr.of(val.val().timer), 1_000_000_000L, 0);
        }
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws InterruptedException {
        try (TimerDemo program = BPFProgram.load(TimerDemo.class)) {
            program.xdpAttach();
            System.out.println("Loaded — send a packet to the default interface to arm the timer.");
            while (true) {
                System.out.printf("Tick count: %d%n", program.tickCount.get());
                Thread.sleep(1000);
            }
        }
    }
}
