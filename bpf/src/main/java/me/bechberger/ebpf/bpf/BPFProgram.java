package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;

import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.shared.TraceLog.TraceFields;
import org.jetbrains.annotations.Nullable;

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
 * }
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

    /**
     * Loads the implementation class of the given abstract BPFProgram subclass
     * <p>
     * Example: {@snippet :
     *    HelloWorld program = BPFProgram.load(HelloWorld.class);
     * }
     * @param clazz abstract BPFProgram subclass
     * @return instance of the implementation class, created using the default constructor
     * @param <T> the abstract BPFProgram subclass
     * @param <S> the implementation class
     */
    @SuppressWarnings("unchecked")
    public static <T extends BPFProgram, S extends T> S load(Class<T> clazz) {
        try {
            String pkg = clazz.getCanonicalName();
            pkg = pkg.substring(0, pkg.lastIndexOf('.')).toLowerCase();
            String name = clazz.getSimpleName() + "Impl";
            return (S) Class.forName(pkg + "." + name).getConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The eBPF object, struct bpf_object *ebpf_object
     */
    private MemorySegment ebpf_object;

    /** Load the eBPF program from the byte code */
    public BPFProgram() {
        this.ebpf_object = loadProgram();
    }

    /**
     * Load the eBPF program from the byte code
     * @return the eBPF object
     * @throws BPFLoadError if the whole program could not be loaded
     */
    private MemorySegment loadProgram() {
        Path objFile = getTmpObjectFile();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment fileName = arena.allocateUtf8String(objFile.toString());
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
     * @param name the name of the program, or null, if the program cannot be found
     * @return the program handle
     * @throws BPFProgramNotFound if the program cannot be found
     */
    public ProgramHandle getProgramByName(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment prog = Lib.bpf_object__find_program_by_name(this.ebpf_object, arena.allocateUtf8String(name));
            if (prog == MemorySegment.NULL || prog.address() == 0) {
                throw new BPFProgramNotFound(name);
            }
            return new ProgramHandle(name, prog);
        }
    }

    /** Thrown when attaching a specific program / entry function fails */
    public static class BPFAttachError extends BPFError {

        public BPFAttachError(String name, int errorCode) {
            super("Failed to attach name", errorCode);
        }
    }

    private static HandlerWithErrno<MemorySegment> BCC_PROGRAM__ATTACH = new HandlerWithErrno<>("bpf_program__attach",
            FunctionDescriptor.of(PanamaUtil.POINTER, PanamaUtil.POINTER)
            );


    /**
     * Attach the program by the automatically detected program type, attach type, and extra paremeters, where applicable.
     * @param prog program to attach
     * @throws BPFAttachError when attaching fails
     */
    public void autoAttachProgram(ProgramHandle prog) {
        var ret = BCC_PROGRAM__ATTACH.call(prog.prog());
        if (ret.result() == MemorySegment.NULL) {
            throw new BPFAttachError(prog.name, ret.err());
        }
    }

    /**
     * Close the program and remove it
     */
    @Override
    public void close() {
        Lib.bpf_object__close(this.ebpf_object);
    }

    /**
     * Print the kernel debug trace pipe
     * <p>
     * @see TraceLog#printLoop()
     */
    public void tracePrintLoop() {
        TraceLog.getInstance().printLoop();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * @param format optional function to format the output
     *
     * Example
     * {@snippet
     *   tracePrintLoop(f -> f.format("pid {1}, msg = {5}"));
     * }
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
}
