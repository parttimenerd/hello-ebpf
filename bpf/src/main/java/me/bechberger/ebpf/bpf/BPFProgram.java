package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.LibraryLoader;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;

import me.bechberger.ebpf.shared.TraceLog;

public abstract class BPFProgram implements AutoCloseable {

    static {
        LibraryLoader.load();
    }

    /**
     * The eBPF object, struct bpf_object *ebpf_object
     */
    private MemorySegment ebpf_object;

    public BPFProgram() {
        this.ebpf_object = loadProgram();
    }

    /**
     * Load the eBPF program from the byte code
     * @return the eBPF object
     */
    private MemorySegment loadProgram() {
        Path objFile = getTmpObjectFile();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment fileName = arena.allocateUtf8String(objFile.toString());
            MemorySegment ebpf_object = Lib.bpf_object__open_file(fileName, MemorySegment.NULL);
            if (ebpf_object == MemorySegment.NULL) {
                throw new RuntimeException("Failed to load eBPF object");
            }
            if (Lib.bpf_object__load(ebpf_object) != 0) {
                throw new RuntimeException("Failed to load eBPF object");
            }
            return ebpf_object;
        }
    }

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

    public record ProgramHandle(String name, MemorySegment prog) {
    }

    public ProgramHandle getProgramByName(String name) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment prog = Lib.bpf_object__find_program_by_name(this.ebpf_object, arena.allocateUtf8String(name));
            if (prog == MemorySegment.NULL || prog.address() == 0) {
                throw new RuntimeException("Failed to find program " + name);
            }
            return new ProgramHandle(name, prog);
        }
    }

    public void autoAttachProgram(ProgramHandle prog) {
        System.out.println("Attaching program " + prog);
        if (Lib.bpf_program__attach(prog.prog) == MemorySegment.NULL) {
            throw new RuntimeException("Failed to attach program " + prog.name());
        }
    }

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

}
