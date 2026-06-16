package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.raw.Lib;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;

/**
 * BPF CPU map ({@code BPF_MAP_TYPE_CPUMAP}) — redirect XDP packets to be
 * processed on a specific CPU.
 *
 * <p>The key is a CPU index and the value is the size of the per-CPU ring
 * buffer (in entries).  A value of 0 removes the CPU slot.
 *
 * <pre>{@code
 *   @BPFMapDefinition(maxEntries = 8)
 *   BPFCpuMap cpuMap;
 *
 *   // user-space: set up CPU 2 with a 512-entry queue
 *   program.cpuMap.put(2, 512);
 *
 *   // BPF-side: redirect to CPU 2
 *   return xdp_action.of((int) BPFJ.bpfRedirectMap(Ptr.of(cpuMap), 2, XDP_PASS));
 * }</pre>
 *
 * <p>Requires Linux ≥ 4.15.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_CPUMAP);
            __uint(key_size, sizeof(u32));
            __uint(value_size, sizeof(u32));
            __uint(max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = "new $class($fd, $maxEntries)")
public class BPFCpuMap extends BPFMap {

    private final int maxEntries;

    public BPFCpuMap(FileDescriptor fd, int maxEntries) {
        super(MapTypeId.CPUMAP, fd);
        this.maxEntries = maxEntries;
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    /**
     * Assigns {@code queueSize} ring-buffer entries to CPU slot {@code cpu}.
     * Pass {@code queueSize=0} to clear the slot.
     *
     * @param cpu       CPU index
     * @param queueSize per-CPU ring buffer size in entries
     * @return {@code true} on success
     */
    public boolean put(@Unsigned int cpu, @Unsigned int queueSize) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, cpu);
            valMem.set(ValueLayout.JAVA_INT, 0, queueSize);
            return Lib.bpf_map_update_elem(getFd().fd(), keyMem, valMem, 0) == 0;
        }
    }

    /**
     * Returns the queue size configured for {@code cpu}, or {@code 0} if not set.
     */
    public @Unsigned int get(@Unsigned int cpu) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, cpu);
            int ret = Lib.bpf_map_lookup_elem(getFd().fd(), keyMem, valMem);
            if (ret != 0) return 0;
            return valMem.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /**
     * Removes CPU slot {@code cpu}.
     */
    public boolean delete(@Unsigned int cpu) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, cpu);
            return Lib.bpf_map_delete_elem(getFd().fd(), keyMem) == 0;
        }
    }

    /**
     * BPF-side: redirect the current XDP packet to CPU {@code cpu}.
     *
     * <p>Returns {@code XDP_REDIRECT} on success; falls back to {@code flags}
     * (use {@code XDP_PASS} or {@code XDP_DROP}) if the slot is empty.
     *
     * <p>Lowers to {@code bpf_redirect_map(&map, cpu, flags)}.
     */
    @BuiltinBPFFunction("bpf_redirect_map(&$this, $arg1, $arg2)")
    @NotUsableInJava
    public @Unsigned long bpf_redirect(@Unsigned long cpu, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }
}
