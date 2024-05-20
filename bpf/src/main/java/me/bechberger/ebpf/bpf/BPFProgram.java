package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.GlobalVariable.Globals;
import me.bechberger.ebpf.bpf.map.*;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer.BPFRingBufferError;
import me.bechberger.ebpf.bpf.processor.Processor;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.bpf.raw.btf_type;
import me.bechberger.ebpf.bpf.raw.btf_var_secinfo;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.shared.TraceLog.TraceFields;
import me.bechberger.ebpf.type.BPFType.BPFStructType;
import me.bechberger.ebpf.type.BPFType.BPFUnionType;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.foreign.AddressLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.function.IntSupplier;
import java.util.stream.IntStream;

/**
 * Base class for bpf programs.
 * <p></p>
 * {@snippet :
 *     @BPF
 *     public static abstract class HelloWorldProgram extends BPFProgram {
 *
 *         static final String EBPF_PROGRAM = """
 *                 #include "vmlinux.h"
 *                 #include <bpf/bpf_helpers.h>
 *                 #include <bpf/bpf_tracing.h>
 *
 *                 SEC ("kprobe/do_sys_openat2") int kprobe__do_sys_openat2 (struct pt_regs *ctx){
 *                     bpf_printk("Hello, World from BPF and more!");
 *                     return 0;
 *                 }
 *
 *                 char _license[] SEC ("license") = "GPL";
 *                 """;
 *     }
 *
 *     public static void main(String[] args) {
 *         try (HelloWorldProgram program = new HelloWorldProgramImpl()) {
 *             program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
 *             program.tracePrintLoop();
 *         }
 *     }
 *}
 */
public abstract class BPFProgram implements AutoCloseable {

    static {
        LibraryLoader.load();
    }

    /**
     * Thrown whenever the whole bpf program could not be loaded
     */
    public static class BPFLoadError extends BPFError {

        public BPFLoadError(String message) {
            super(message);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T, S extends T> Class<S> getImplClass(Class<T> clazz) {
        try {
            var implName = Processor.classToImplName(clazz);
            return (Class<S>)Class.forName(implName.fullyQualifiedClassName());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads the implementation class of the given abstract BPFProgram subclass
     * <p>
     * Example: {@snippet :
     *    HelloWorld program = BPFProgram.load(HelloWorld.class);
     *}
     *
     * @param clazz abstract BPFProgram subclass
     * @param <T>   the abstract BPFProgram subclass
     * @param <S>   the implementation class
     * @return instance of the implementation class, created using the default constructor
     */
    public static <T extends BPFProgram, S extends T> S load(Class<T> clazz) {
        try {
            var program = BPFProgram.<T, S>getImplClass(clazz).getConstructor().newInstance();
            program.initGlobals();
            return program;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The eBPF object, struct bpf_object *ebpf_object
     */
    private final MemorySegment ebpf_object;

    /**
     * Link to an attached program
     */
    public record BPFLink(MemorySegment segment) {}

    private final Set<BPFLink> attachedPrograms = new HashSet<>();

    private final Set<BPFMap> attachedMaps = new HashSet<>();

    record AttachedXDPIfIndex(int ifindex, int flags) {}

    private final Set<AttachedXDPIfIndex> attachedXDPIfIndexes = new HashSet<>();

    private volatile boolean closed = false;

    /**
     * Load the eBPF program from the byte code
     * <p>
     * You have to call {@link #initGlobals()} to initialize the global variables
     */
    public BPFProgram() {
        this.ebpf_object = loadProgram();
        Runtime.getRuntime().addShutdownHook(new Thread(this::close));
    }

    protected void initGlobals() {
    }

    public <T> BPFType<T> getTypeForClass(Class<T> innerType) {
        return getTypeForImplClass(getClass(), innerType);
    }

    public static <T> BPFType<T> getTypeForClass(Class<?> outer, Class<T> inner) {
        return getTypeForImplClass(getImplClass(outer), inner);
    }

    public <T> BPFStructType<T> getStructTypeForClass(Class<T> innerType) {
        return (BPFStructType<T>) getTypeForImplClass(getClass(), innerType);
    }

    public static <T> BPFStructType<T> getStructTypeForClass(Class<?> outer, Class<T> inner) {
        return (BPFStructType<T>) getTypeForImplClass(getImplClass(outer), inner);
    }

    public <T extends Union> BPFUnionType<T> getUnionTypeForClass(Class<T> innerType) {
        return (BPFUnionType<T>) getTypeForImplClass(getClass(), innerType);
    }

    public static <T extends Union> BPFUnionType<T> getUnionTypeForClass(Class<?> outer, Class<T> inner) {
        return (BPFUnionType<T>) getTypeForImplClass(getImplClass(outer), inner);
    }

    private static <T> BPFType<T> getTypeForImplClass(Class<?> outerImpl, Class<T> inner) {
        try {
            return getTypeForImplClass(outerImpl, inner, true);
        } catch (Exception e) {
            return getTypeForImplClass(outerImpl, inner, false);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> BPFType<T> getTypeForImplClass(Class<?> outerImpl, Class<T> inner, boolean canonical) {
        String fieldName = (canonical ? inner.getCanonicalName() : inner.getSimpleName()).replaceAll("([a-z0-9])([A-Z])", "$1_$2")
                .replace(".", "__").toUpperCase();
        try {
            return (BPFType<T>) outerImpl.getDeclaredField(fieldName).get(null);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Load the eBPF program from the byte code
     *
     * @return the eBPF object
     * @throws BPFLoadError if the whole program could not be loaded
     */
    private MemorySegment loadProgram() {
        Path objFile = getTmpObjectFile();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment fileName = arena.allocateFrom(objFile.toString());
            MemorySegment ebpf_object = Lib.bpf_object__open_file(fileName, MemorySegment.NULL);
            if (ebpf_object == MemorySegment.NULL) {
                throw new BPFLoadError("Failed to load eBPF object");
            }
            if (Lib.bpf_object__load(ebpf_object) != 0) {
                throw new BPFLoadError("Failed to load eBPF object");
            }
            return ebpf_object;
        }
    }

    /**
     * Get the byte code of the bpf program.
     *
     * @return the byte code
     */
    public abstract byte[] getByteCode();

    private Path getTmpObjectFile() {
        try {
            Path tmp = Files.createTempFile("bpf", ".o");
            tmp.toFile().deleteOnExit();
            try (var os = Files.newOutputStream(tmp)) {
                os.write(getByteCode());
            }
            return tmp;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * A handle to an ebpf program (an entry point function in the eBPF program)
     */
    public record ProgramHandle(String name, MemorySegment prog) {
    }

    public static class BPFProgramNotFound extends BPFError {
        public BPFProgramNotFound(String name) {
            super("Program not found: " + name);
        }
    }

    /**
     * Get a program handle by name
     *
     * @param name the name of the program, or null, if the program cannot be found
     * @return the program handle
     * @throws BPFProgramNotFound if the program cannot be found
     */
    public ProgramHandle getProgramByName(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment prog = Lib.bpf_object__find_program_by_name(this.ebpf_object, arena.allocateFrom(name));
            if (prog == MemorySegment.NULL || prog.address() == 0) {
                throw new BPFProgramNotFound(name);
            }
            return new ProgramHandle(name, prog);
        }
    }

    /**
     * Thrown when attaching a specific program / entry function fails
     */
    public static class BPFAttachError extends BPFError {

        public BPFAttachError(String name, int errorCode) {
            super("Failed to attach name", errorCode);
        }
    }

    private static final HandlerWithErrno<MemorySegment> BPF_PROGRAM__ATTACH =
            new HandlerWithErrno<>("bpf_program__attach",
                    FunctionDescriptor.of(PanamaUtil.POINTER, PanamaUtil.POINTER));


    /**
     * Attach the program by the automatically detected program type, attach type, and extra paremeters, where
     * applicable.
     *
     * @param prog program to attach
     * @throws BPFAttachError when attaching fails
     */
    public BPFLink autoAttachProgram(ProgramHandle prog) {
        var ret = BPF_PROGRAM__ATTACH.call(prog.prog());
        if (ret.result() == MemorySegment.NULL) {
            throw new BPFAttachError(prog.name, ret.err());
        }
        var link = new BPFLink(ret.result());
        attachedPrograms.add(link);
        return link;
    }

    public void xdpAttach(ProgramHandle prog, int ifindex) {
        int flags = XDPUtil.XDP_FLAGS_UPDATE_IF_NOEXIST | XDPUtil.XDP_FLAGS_DRV_MODE;
        int fd = Lib.bpf_program__fd(prog.prog());
        int err = Lib.bpf_xdp_attach(ifindex, fd, flags, MemorySegment.NULL);
        if (err > 0) {
            throw new BPFAttachError(prog.name, err);
        }
        attachedXDPIfIndexes.add(new AttachedXDPIfIndex(ifindex, flags));
    }

    public void detachProgram(BPFLink link) {
        if (!attachedPrograms.contains(link)) {
            throw new IllegalArgumentException("Program not attached");
        }
        if (link.segment.address() == 0) {
            throw new IllegalArgumentException("Improper link");
        }
        Lib.bpf_link__destroy(link.segment);
        System.out.println("Detached program " + getClass().getCanonicalName());
        attachedPrograms.remove(link);
    }

    /**
     * Close the program and remove it
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        for (var prog : new HashSet<>(attachedPrograms)) {
            detachProgram(prog);
        }
        for (var ifindex : new HashSet<>(attachedXDPIfIndexes)) {
            Lib.bpf_xdp_detach(ifindex.ifindex, ifindex.flags, MemorySegment.NULL);
        }
        for (var map : new HashSet<>(attachedMaps)) {
            map.close();
        }
        Lib.bpf_object__close(this.ebpf_object);
    }

    /**
     * Print the kernel debug trace pipe
     * <p>
     *
     * @see TraceLog#printLoop()
     */
    public void tracePrintLoop() {
        TraceLog.getInstance().printLoop();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     *
     * @param format optional function to format the output
     *               <p>
     *               Example
     *               {@snippet *tracePrintLoop(f->f.format("pid {1}, msg = {5}"));
     *}
     */
    public void tracePrintLoop(Function<TraceFields, @Nullable String> format) {
        TraceLog.getInstance().printLoop(format);
    }

    public String readTraceLine() {
        return TraceLog.getInstance().readLine();
    }

    public TraceFields readTraceFields() {
        return TraceLog.getInstance().readFields();
    }


    /**
     * Thrown when a map could not be found
     */
    public static class BPFMapNotFoundError extends BPFError {
        public BPFMapNotFoundError(String name) {
            super("Map not found: " + name);
        }
    }

    /**
     * Get a map descriptor by name
     *
     * @param name the name of the map
     * @return the map descriptor
     * @throws BPFMapNotFoundError if the map cannot be found
     */
    public FileDescriptor getMapDescriptorByName(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment map = Lib.bpf_object__find_map_by_name(this.ebpf_object, arena.allocateFrom(name));
            if (map == MemorySegment.NULL || map.address() == 0) {
                throw new BPFMapNotFoundError(name);
            }
            return new FileDescriptor(name, map, Lib.bpf_map__fd(map));
        }
    }

    public <T extends BPFMap> T recordMap(T map) {
        attachedMaps.add(map);
        return map;
    }

    /**
     * Get a map by name
     *
     * @param name       the name of the map
     * @param mapCreator function to create the map
     * @param <M>        the type of the map
     * @return the map
     * @throws BPFMapNotFoundError       if the map cannot be found
     * @throws BPFMap.BPFMapTypeMismatch if the type of the map does not match the expected type
     */
    public <M extends BPFMap> M getMapByName(String name, Function<FileDescriptor, M> mapCreator) {
        return recordMap(mapCreator.apply(getMapDescriptorByName(name)));
    }

    /**
     * Get a ring buffer by name
     * <p>
     * Keep in mind to regularly call {@link BPFRingBuffer#consumeAndThrow()} to consume the events
     *
     * @param name      the name of the ring buffer
     * @param eventType type of the event
     * @param callback  callback that is called when a new event is received
     * @param <E>       the type of the event
     * @return the ring buffer
     * @throws BPFMapNotFoundError              if the ring buffer cannot be found
     * @throws BPFMap.BPFMapTypeMismatch        if the type of the ring buffer does not match the expected type
     * @throws BPFRingBuffer.BPFRingBufferError if the ring buffer could not be created
     */
    public <E> BPFRingBuffer<E> getRingBufferByName(String name, BPFType<E> eventType,
                                                    BPFRingBuffer.EventCallback<E> callback) {
        return recordMap(getMapByName(name, fd -> new BPFRingBuffer<>(fd, eventType, callback)));
    }

    public <K, V> BPFHashMap<K, V> getHashMapByName(String name, BPFType<K> keyType,
                                                    BPFType<V> valueType) {
        var fd = getMapDescriptorByName(name);
        MapTypeId type = BPFMap.getInfo(fd).type();
        return recordMap(new BPFHashMap<>(fd, type == MapTypeId.LRU_HASH, keyType, valueType));
    }

    /**
     * Polls data from all ring buffers and consumes if available.
     *
     * @throws BPFRingBufferError if calling the consume method failed,
     *         or if any errors were caught in the call-back of any ring buffer
     */
    public void consumeAndThrow() {
        for (var map : attachedMaps) {
            if (map instanceof BPFRingBuffer) {
                ((BPFRingBuffer<?>)map).consumeAndThrow();
            }
        }
    }

    public static class BTF {

        private final MemorySegment bpfObject;
        private Map<Integer, BTFType> types = new HashMap<>();

        BTF(MemorySegment bpfObject) {
            this.bpfObject = bpfObject;
        }

        public enum Kind {
            UNKN(0),
            INT(1),
            PTR(2),
            ARRAY(3),
            STRUCT(4),
            UNION(5),
            ENUM(6),
            FWD(7),
            TYPEDEF(8),
            VOLATILE(9),
            CONST(10),
            RESTRICT(11),
            FUNC(12),
            FUNC_PROTO(13),
            VAR(14),
            DATASEC(15),
            FLOAT(16),
            DECL_TAG(17),
            TYPE_TAG(18),
            ENUM64(19);

            private final int value;

            Kind(int value) {
                this.value = value;
            }

            public int value() {
                return value;
            }

            public static Kind fromValue(int value) {
                return values()[value];
            }
        }

        public static class BTFType {

            private static int kind(int info) {
                return (info >> 24) & 0xff;
            }

            private static int vlen(int info) {
                return info & 0xffff;
            }

            private final BTF btf;
            private final MemorySegment typeObj;
            private final Kind kind;
            private final String name;

            public BTFType(BTF btf, MemorySegment typeObj) {
                this.btf = btf;
                this.typeObj = typeObj;
                this.kind = Kind.fromValue(kind(btf_type.info(typeObj)));
                this.name = PanamaUtil.toString(Lib.btf__name_by_offset(btf.bpfObject, btf_type.name_off(typeObj)));
            }

            Kind kind() {
                return kind;
            }

            String name() {
                return name;
            }

            int memberCount() {
                return vlen(btf_type.info(typeObj));
            }

            record VariableSectionInfo(BTFType type, int offset, int size) {
                String name() {
                    return type.name;
                }
            }

            List<VariableSectionInfo> getVariableSectionInfos() {
                // in c code:
                // btf_var_secinfo *ptr = (struct btf_var_secinfo *)(type + 1);
                // assume that btf_var_secinfo and btf_type are 4 byte aligned
                var infos = typeObj.address() + btf_type.sizeof();
                return IntStream.range(0, memberCount()).mapToObj(i -> {
                    var elem = MemorySegment.ofAddress(infos + i * btf_var_secinfo.sizeof()).reinterpret(btf_var_secinfo.sizeof());
                    return new VariableSectionInfo(btf.getTypeById(btf_var_secinfo.type(elem)), btf_var_secinfo.offset(elem), btf_var_secinfo.size(elem));
                }).toList();
            }
        }

        int findIdByName(String name) {
            try (Arena arena = Arena.ofConfined()) {
                int id = Lib.btf__find_by_name(bpfObject, arena.allocateFrom(name));
                if (id < 0) {
                    throw new BPFError("Failed to find BTF by name: " + name);
                }
                return id;
            }
        }

        BTFType getTypeById(int id) {
            return types.computeIfAbsent(id, i -> {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment segment = Lib.btf__type_by_id(bpfObject, id);
                    if (segment == MemorySegment.NULL) {
                        throw new BPFError("Failed to get BTF type by id: " + id);
                    }
                    return new BTFType(this, segment);
                }
            });
        }

        BTFType findTypeByName(String name) {
            return getTypeById(findIdByName(name));
        }
    }

    private BTF btf = null;

    public BTF getBTF() {
        if (btf == null) {
            var ret = Lib.bpf_object__btf(this.ebpf_object);
            if (Lib.libbpf_get_error(ret) != 0) {
                throw new BPFError("Failed to get BTF");
            }
            btf = new BTF(ret);
        }
        return btf;
    }
}