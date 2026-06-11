package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.bpf.BPFError;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.raw.Lib;

import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;

/**
 * eBPF program array map ({@code BPF_MAP_TYPE_PROG_ARRAY}).
 *
 * <p>Used for tail calls: a slot in the array holds a program fd, and calling
 * {@link #tailCall(Object, int)} transfers execution to that program without
 * returning. Programs are registered at runtime via
 * {@link #register(int, BPFProgram.ProgramHandle)}.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint (type, BPF_MAP_TYPE_PROG_ARRAY);
            __uint (key_size, sizeof(u32));
            __uint (value_size, sizeof(u32));
            __uint (max_entries, $maxEntries);
        } $field SEC(".maps");
        """,
        javaTemplate = "new $class($fd, $maxEntries)")
public class BPFProgArray extends BPFMap {

    private final int maxEntries;

    public BPFProgArray(FileDescriptor fd, int maxEntries) {
        super(MapTypeId.PROG_ARRAY, fd);
        this.maxEntries = maxEntries;
    }

    public int getMaxEntries() {
        return maxEntries;
    }

    /**
     * Tail-call into the program stored at {@code slot}.
     *
     * <p>In BPF this lowers to {@code bpf_tail_call(ctx, &map, slot)}.
     * The call never returns — execution continues in the target program.
     * On Java side this method always throws.
     *
     * @param ctx  the BPF context passed to the current program
     * @param slot index into the program array
     */
    @BuiltinBPFFunction("bpf_tail_call($arg1, &$this, $arg2)")
    @NotUsableInJava
    public void tailCall(Object ctx, int slot) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * Register a BPF program at the given slot.
     *
     * @param slot   slot index (0 ≤ slot &lt; maxEntries)
     * @param handle program handle obtained from
     *               {@link BPFProgram#getProgramByName(String)}
     * @throws BPFError if the map update fails
     */
    public void register(int slot, BPFProgram.ProgramHandle handle) {
        int progFd = Lib.bpf_program__fd(handle.prog());
        register(slot, progFd);
    }

    /**
     * Register a BPF program file descriptor at the given slot.
     *
     * @param slot  slot index
     * @param progFd BPF program file descriptor
     * @throws BPFError if the map update fails
     */
    public void register(int slot, int progFd) {
        try (var arena = Arena.ofConfined()) {
            var keyMem = arena.allocate(ValueLayout.JAVA_INT);
            keyMem.set(ValueLayout.JAVA_INT, 0, slot);
            var valMem = arena.allocate(ValueLayout.JAVA_INT);
            valMem.set(ValueLayout.JAVA_INT, 0, progFd);
            int ret = Lib.bpf_map_update_elem(fd.fd(), keyMem, valMem, Lib.BPF_ANY());
            if (ret != 0) {
                throw new BPFError("Failed to register program at slot " + slot, ret);
            }
        }
    }
}
