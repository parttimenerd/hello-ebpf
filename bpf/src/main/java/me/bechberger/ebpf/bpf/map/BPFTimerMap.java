package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.BpfDefinitions.bpf_timer;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * A BPF hash map keyed by {@code u32} whose value bundles a
 * {@link bpf_timer} with a one-shot initialisation flag ({@link TimerVal}).
 *
 * <p>Eliminates the need to re-declare the map struct and the
 * {@link TimerVal} type at every call site.
 *
 * <p>Typical usage inside a {@code @BPF} program:
 * <pre>{@code
 *   @BPFMapDefinition(maxEntries = 1)
 *   BPFTimerMap<BPFTimerMap.TimerVal> timerMap;
 *
 *   // arm on first packet / first wakeup:
 *   Ptr<BPFTimerMap.TimerVal> slot = timerMap.bpf_get(0);
 *   if (slot != null && slot.val().initialized == 0) {
 *       slot.val().initialized = 1;
 *       bpf_timer_init(Ptr.of(slot.val().timer), Ptr.of(timerMap), 1);
 *       BPFJ.bpf_timer_set_callback(Ptr.of(slot.val().timer), this::onTimer);
 *       bpf_timer_start(Ptr.of(slot.val().timer), 500_000_000L, 0);
 *   }
 *
 *   // callback must carry @BPFTimer @BPFFunction:
 *   @BPFTimer @BPFFunction
 *   public int onTimer(Ptr<?> map, Ptr<Integer> key, Ptr<BPFTimerMap.TimerVal> val) {
 *       bpf_timer_start(Ptr.of(val.val().timer), 500_000_000L, 0);
 *       return 0;
 *   }
 * }</pre>
 *
 * <p>Java (user-space) side — seed slot 0 before attaching so the hook finds it:
 * <pre>{@code
 *   BPFTimerMap.TimerVal v = new BPFTimerMap.TimerVal();
 *   v.timer = BPFJ.newZeroedTimer();
 *   program.timerMap.put(0, v);
 * }</pre>
 *
 * <p>Restriction: {@code bpf_timer} is only available in network / sk_msg /
 * struct_ops / cgroup program types.  It is NOT available in kprobe or
 * tracepoint programs.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_HASH);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, u32);
            __type(value, $c1);
            __uint(max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFTimerMap<V extends BPFTimerMap.TimerVal> extends BPFBaseMap<@Unsigned Integer, V> {

    /** Map value: the kernel timer state plus a one-shot initialisation flag. */
    @Type
    public static class TimerVal {
        public bpf_timer timer;
        public @Unsigned int initialized;
    }

    public BPFTimerMap(FileDescriptor fd, BPFType<V> valueType) {
        super(fd, MapTypeId.HASH, BPFType.BPFIntType.UINT32, valueType);
    }

    /**
     * BPF-side: look up the timer slot by key.
     *
     * <p>Lowers to {@code bpf_map_lookup_elem(&map, &key)}.
     */
    @BuiltinBPFFunction("bpf_map_lookup_elem(&$this, $pointery$arg1)")
    @NotUsableInJava
    public Ptr<V> bpf_get(@Unsigned int key) {
        throw new MethodIsBPFRelatedFunction();
    }
}
