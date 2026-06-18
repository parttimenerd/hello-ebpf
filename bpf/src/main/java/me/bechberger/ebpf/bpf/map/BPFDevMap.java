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
 * BPF devmap ({@code BPF_MAP_TYPE_DEVMAP}) — an array of output network-device
 * interface indices used by XDP programs to bulk-redirect packets.
 *
 * <p>Load a devmap alongside your XDP program, populate it with target
 * {@code ifindex} values from user space, then call
 * {@link me.bechberger.ebpf.bpf.BPFJ#bpfRedirectMap(me.bechberger.ebpf.type.Ptr, long, long)}
 * inside the XDP hook to forward the packet:
 *
 * <pre>{@code
 *   @BPFMapDefinition(maxEntries = 8)
 *   BPFDevMap devMap;
 *
 *   @Override
 *   public xdp_action xdpHandlePacket(XDPContext ctx) {
 *       int cpu = BPFJ.currentCpuId();
 *       return xdp_action.of((int) BPFJ.bpfRedirectMap(Ptr.of(devMap), cpu, XDP_PASS));
 *   }
 * }</pre>
 *
 * <p>User-space setup:
 * <pre>{@code
 *   program.devMap.put(0, 3);  // redirect slot 0 → ifindex 3
 * }</pre>
 *
 * <p>Requires Linux ≥ 4.14.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_DEVMAP);
            __uint(key_size, sizeof(u32));
            __uint(value_size, sizeof(u32));
            __uint(max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = "new $class($fd, $maxEntries)")
public class BPFDevMap extends BPFMap {

    private final int maxEntries;

    public BPFDevMap(FileDescriptor fd, int maxEntries) {
        super(MapTypeId.DEVMAP, fd);
        this.maxEntries = maxEntries;
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    /**
     * Stores {@code ifindex} at slot {@code key}.
     *
     * @param key     slot index (0 ≤ key < maxEntries)
     * @param ifindex output interface index (0 = remove the entry)
     * @return {@code true} on success
     */
    public boolean put(@Unsigned int key, @Unsigned int ifindex) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, key);
            valMem.set(ValueLayout.JAVA_INT, 0, ifindex);
            int ret = Lib.bpf_map_update_elem(getFd().fd(), keyMem, valMem, 0);
            return ret == 0;
        }
    }

    /**
     * Returns the {@code ifindex} stored at {@code key}, or {@code 0} if not set.
     */
    public @Unsigned int get(@Unsigned int key) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, key);
            int ret = Lib.bpf_map_lookup_elem(getFd().fd(), keyMem, valMem);
            if (ret != 0) return 0;
            return valMem.get(ValueLayout.JAVA_INT, 0);
        }
    }

    /**
     * Removes the entry at {@code key}.
     */
    public boolean delete(@Unsigned int key) {
        try (Arena arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, key);
            return Lib.bpf_map_delete_elem(getFd().fd(), keyMem) == 0;
        }
    }

    /**
     * BPF-side: redirect the current packet to the interface stored at {@code key}.
     *
     * <p>Returns {@code XDP_REDIRECT} on success; falls back to {@code flags}
     * (use {@code XDP_PASS} or {@code XDP_DROP}) if the slot is empty.
     *
     * <p>Lowers to {@code bpf_redirect_map(&map, key, flags)}.
     */
    @BuiltinBPFFunction("bpf_redirect_map(&$this, $arg1, $arg2)")
    @NotUsableInJava
    public @Unsigned long bpf_redirect(@Unsigned long key, @Unsigned long flags) {
        throw new MethodIsBPFRelatedFunction();
    }
}
