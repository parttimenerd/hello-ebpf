package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.bpf.BPFProgram.BTF.BTFType.VariableSectionInfo;
import me.bechberger.ebpf.bpf.map.BPFMap;
import me.bechberger.ebpf.bpf.raw.Lib_1;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.type.BPFType;

import java.lang.foreign.Arena;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A global variable in the eBPF program, which can be read and written both from Java and the eBPF program.
 * <p>
 * Requirements
 * <ul>
 *     <li>The type arguments has to be a type that would also be valid in
 *     {@link Type}</li>
 *     <li>The variable has to be final and non-static</li>
 *     <li>The variable has to be initialized with a value wrapped in a {@link GlobalVariable} constructor</li>
 * </ul>
 * <p>
 * Example: {@snippet :
 *   public final GlobalVariable<Integer> count = new GlobalVariable<>(42);
 *
 *   // later:
 *   count.set(43);
 *   int currentCount = count.get();
 *
 *   // in the eBPF program:
 *   ... bpf_printk("Count: %d\n", count); // just a normal global variable
 *}
 *
 * @param <T>
 */
public class GlobalVariable<T> {

    public record GlobalVariableInitInfo<T>(GlobalVariable<T> variable, String name, BPFType<T> type) {
    }

    /**
     * Stores the data of the .data section of the eBPF program
     */
    public static class Globals {
        private final BPFMap dataMap;
        private final Map<String, Integer> offsetsPerVariable;

        private Globals(BPFMap dataMap, Map<String, Integer> offsetsPerVariable) {
            this.dataMap = dataMap;
            this.offsetsPerVariable = offsetsPerVariable;
        }

        public static Globals forProgram(BPFProgram program) {
            var dataMap = new BPFMap(null, program.getMapDescriptorByName(".data"));
            return new Globals(dataMap, findOffsetsPerVariable(program));
        }

        /**
         * Based on <a href="https://stackoverflow.com/a/70485885/19040822">Dylan's stackoverflow answer</a>
         */
        private static Map<String, Integer> findOffsetsPerVariable(BPFProgram program) {
            // read all keys and values from the map
            try (var arena = Arena.ofConfined()) {
                var btf = program.getBTF();
                return btf.findTypeByName(".data").getVariableSectionInfos().stream().collect(Collectors.toMap(
                        VariableSectionInfo::name,
                        VariableSectionInfo::offset
                ));
            }
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        public void set(Map<GlobalVariable<?>, ?> values) {
            try (var arena = Arena.ofConfined()) {
                // Create buffer the size of .data
                var buffer = arena.allocate(dataMap.getInfo().valueSize());
                // Read .data into the buffer
                var zeroRef = PanamaUtil.allocateIntRef(arena, 0);
                var ret = Lib_1.bpf_map_lookup_elem(dataMap.getFd().fd(), zeroRef, buffer);
                if (ret < 0) {
                    throw new BPFError("Failed to read .data", ret);
                }
                // Write the value to the buffer
                for (var entry : values.entrySet()) {
                    var globalVariable = entry.getKey();
                    var value = entry.getValue();
                    Integer offset = offsetsPerVariable.get(globalVariable.name);
                    if (offset == null) {
                        throw new BPFError("GlobalVariable '" + globalVariable.name + "' not found in .data section", -1);
                    }
                    (((GlobalVariable) globalVariable)).type.setMemory(buffer.asSlice(offset), value);
                }
                // Write the buffer back to .data
                ret = Lib_1.bpf_map_update_elem(dataMap.getFd().fd(), zeroRef, buffer, 0);
                if (ret < 0) {
                    throw new BPFError("Failed to write .data", ret);
                }
            }
        }

        public <T> void set(String name, GlobalVariable<T> globalVariable, T value) {
            set(Map.of(globalVariable, value));
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        public void initGlobals(List<GlobalVariableInitInfo<?>> globalVariables) {
            for (var globalVariable : globalVariables) {
                globalVariable.variable.init(this, (BPFType) globalVariable.type, globalVariable.name);
            }
            set(globalVariables.stream().collect(Collectors.toMap(GlobalVariableInitInfo::variable,
                    i -> i.variable.initialValue)));
        }

        public <T> T get(String name, BPFType<T> type) {
            try (var arena = Arena.ofConfined()) {
                // Create buffer the size of .data
                var buffer = arena.allocate(dataMap.getInfo().valueSize());
                // Read .data into the buffer
                var zeroRef = PanamaUtil.allocateIntRef(arena, 0);
                var ret = Lib_1.bpf_map_lookup_elem(dataMap.getFd().fd(), zeroRef, buffer);
                if (ret < 0) {
                    throw new BPFError("Failed to read .data", ret);
                }
                // Read the value from the buffer
                Integer offset = offsetsPerVariable.get(name);
                if (offset == null) {
                    throw new BPFError("GlobalVariable '" + name + "' not found in .data section", -1);
                }
                return type.parseMemory(buffer.asSlice(offset));
            }
        }
    }

    private final T initialValue;
    private Globals globals;
    private BPFType<T> type;
    private String name;

    public GlobalVariable(T initialValue) {
        this.initialValue = initialValue;
    }

    /**
     * Used internally to set this variable up
     */
    public void init(Globals globals, BPFType<T> type, String name) {
        this.globals = globals;
        this.type = type;
        this.name = name;
    }

    /**
     * Set the value of this global variable
     */
    @BuiltinBPFFunction("$this = $arg1")
    public void set(T value) {
        if (globals == null) throw new IllegalStateException("GlobalVariable '" + name + "' used before BPFProgram.load()");
        globals.set(name, this, value);
    }

    /**
     * Get the current value of this global variable
     */
    @BuiltinBPFFunction("$this")
    public T get() {
        if (globals == null) throw new IllegalStateException("GlobalVariable '" + name + "' used before BPFProgram.load()");
        return globals.get(name, type);
    }

    /**
     * Atomically adds {@code delta} to this variable and returns the new value.
     * <p>In BPF programs this lowers to {@code __sync_fetch_and_add}, which emits
     * a {@code BPF_ATOMIC} instruction understood by the kernel verifier.
     * <p>On the Java side the operation is a non-atomic read-modify-write; use
     * only when no concurrent BPF program is modifying the variable.
     */
    @BuiltinBPFFunction("__sync_fetch_and_add(&$this, $arg1) + $arg1")
    @SuppressWarnings("unchecked")
    public T addAndGet(T delta) {
        T current = get();
        T newVal = addValues(current, delta);
        set(newVal);
        return newVal;
    }

    /**
     * Atomically increments this variable by 1 and returns the new value.
     * <p>See {@link #addAndGet} for atomicity guarantees.
     */
    @BuiltinBPFFunction("__sync_fetch_and_add(&$this, 1) + 1")
    public T incrementAndGet() {
        return addAndGet(oneValue());
    }

    /**
     * Atomically sets this variable to {@code update} if the current value equals
     * {@code expected}, and returns {@code true} if the swap occurred.
     * <p>In BPF programs this lowers to {@code __sync_val_compare_and_swap}.
     * <p>On the Java side the operation is a non-atomic read-compare-write.
     */
    @BuiltinBPFFunction("__sync_val_compare_and_swap(&$this, $arg1, $arg2) == $arg1")
    public boolean compareAndSet(T expected, T update) {
        T current = get();
        if (current.equals(expected)) {
            set(update);
            return true;
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private T addValues(T a, T b) {
        if (a instanceof Long la && b instanceof Long lb) return (T) Long.valueOf(la + lb);
        if (a instanceof Integer ia && b instanceof Integer ib) return (T) Integer.valueOf(ia + ib);
        if (a instanceof Short sa && b instanceof Short sb) return (T) Short.valueOf((short) (sa + sb));
        if (a instanceof Byte ba && b instanceof Byte bb) return (T) Byte.valueOf((byte) (ba + bb));
        throw new UnsupportedOperationException("addAndGet requires a numeric type, got " + a.getClass());
    }

    @SuppressWarnings("unchecked")
    private T oneValue() {
        T current = get();
        if (current instanceof Long) return (T) Long.valueOf(1L);
        if (current instanceof Integer) return (T) Integer.valueOf(1);
        if (current instanceof Short) return (T) Short.valueOf((short) 1);
        if (current instanceof Byte) return (T) Byte.valueOf((byte) 1);
        throw new UnsupportedOperationException("incrementAndGet requires a numeric type, got " + current.getClass());
    }
}
