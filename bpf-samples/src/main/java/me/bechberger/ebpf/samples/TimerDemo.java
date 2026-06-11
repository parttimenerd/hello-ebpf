package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFTimer;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.NetworkUtil;
import me.bechberger.ebpf.bpf.XDPHook;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_action;
import me.bechberger.ebpf.runtime.XdpDefinitions.xdp_md;
import me.bechberger.ebpf.type.Ptr;

/**
 * Demonstrates BPF timers: a 1-second self-rearming kernel-side timer.
 *
 * <p>On the first incoming packet the XDP hook initializes a {@code bpf_timer}
 * stored in a hash map. The timer fires every second, incrementing
 * {@code tickCount}. The current tick count is printed from Java.
 *
 * <p>Design note: the timer callback ({@link #timerCallback}) uses a raw C
 * string body because the compiler plugin does not yet support passing a
 * Java method reference as a {@code bpf_timer_set_callback} function pointer.
 * The {@link BPFTimer} annotation marks the callback for future auto-wiring.
 *
 * <p>Usage (requires root):
 * <pre>
 *   sudo ./run.sh TimerDemo
 * </pre>
 */
@BPF(license = "GPL")
public abstract class TimerDemo extends BPFProgram implements XDPHook {

    /** The timer map struct is declared in the raw C header below. */
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

    /** Tick counter — incremented by the timer callback every second. */
    final GlobalVariable<@Unsigned Integer> tickCount = new GlobalVariable<>(0);

    /**
     * BPF timer callback: increments the tick counter and re-arms for 1 s.
     *
     * <p>Raw C body is required because function pointers for
     * {@code bpf_timer_set_callback} are not yet supported by the plugin.
     */
    @BPFTimer
    @BPFFunction
    public int timerCallback(Ptr<?> map, Ptr<Integer> key, Ptr<?> val) {
        String code = """
                tickCount++;
                bpf_timer_start(&((struct timer_val *)val)->timer, 1000000000ULL, 0);
                return 0;
                """;
        return 0;
    }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        String code = """
                __u32 key = 0;
                struct timer_val *val = bpf_map_lookup_elem(&timer_map, &key);
                if (!val) return XDP_PASS;
                if (!val->initialized) {
                    val->initialized = 1;
                    bpf_timer_init(&val->timer, &timer_map, 1 /* CLOCK_MONOTONIC */);
                    bpf_timer_set_callback(&val->timer, timerCallback);
                    bpf_timer_start(&val->timer, 1000000000ULL, 0);
                }
                return XDP_PASS;
                """;
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
