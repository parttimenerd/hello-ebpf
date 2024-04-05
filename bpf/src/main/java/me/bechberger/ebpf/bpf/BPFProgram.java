package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.bpf.map.*;
import me.bechberger.ebpf.bpf.map.BPFRingBuffer.BPFRingBufferError;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.shared.TraceLog.TraceFields;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

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
            String pkg = clazz.getCanonicalName();
            pkg = pkg.substring(0, pkg.lastIndexOf('.')).toLowerCase();
            String name = clazz.getSimpleName() + "Impl";
            return (Class<S>)Class.forName(pkg + "." + name);
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
            return BPFProgram.<T, S>getImplClass(clazz).getConstructor().newInstance();
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

    private volatile boolean closed = false;

    /**
     * Load the eBPF program from the byte code
     */
    public BPFProgram() {
        this.ebpf_object = loadProgram();
        Runtime.getRuntime().addShutdownHook(new Thread(this::close));
    }

    public <T> BPFType.BPFStructType<T> getTypeForClass(Class<T> innerType) {
        return getTypeForImplClass(getClass(), innerType);
    }

    public static <T> BPFType.BPFStructType<T> getTypeForClass(Class<?> outer, Class<T> inner) {
        return getTypeForImplClass(getImplClass(outer), inner);
    }

    @SuppressWarnings("unchecked")
    private static <T> BPFType.BPFStructType<T> getTypeForImplClass(Class<?> outerImpl, Class<T> inner) {
        String fieldName = inner.getSimpleName().replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase();

        try {
            return (BPFType.BPFStructType<T>) outerImpl.getDeclaredField(fieldName).get(null);
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
            return new FileDescriptor(name, Lib.bpf_map__fd(map));
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
     * @return the number of events consumed (max MAX_INT)
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
}