package me.bechberger.ebpf.bpf;

import jdk.jfr.*;

/**
 * JFR events emitted by the BPF runtime.
 *
 * <p>These events show up in {@code jcmd <pid> JFR.start} / {@code jcmd <pid> JFR.dump}
 * recordings and in JDK Mission Control under the "BPF" category.
 *
 * <p>All events are disabled by default so that programs that don't use JFR incur zero
 * overhead. Enable them via a JFR configuration file or with
 * {@code -XX:StartFlightRecording:settings=...}.
 */
public final class BPFEvents {

    private BPFEvents() {}

    /**
     * Fired once per BPF object load (i.e. per {@link BPFProgram#load}).
     */
    @Name("me.bechberger.ebpf.ProgramLoad")
    @Label("BPF Program Load")
    @Category({"BPF"})
    @Description("A BPF object was loaded into the kernel.")
    @StackTrace(false)
    public static class ProgramLoad extends Event {
        @Label("Program Class")
        public String programClass;

        @Label("Duration (ms)")
        public long durationMs;
    }

    /**
     * Fired when a BPF entry point is attached (e.g. via {@link BPFProgram#autoAttachProgram}).
     */
    @Name("me.bechberger.ebpf.ProgramAttach")
    @Label("BPF Program Attach")
    @Category({"BPF"})
    @Description("A BPF program entry point was attached to a hook.")
    @StackTrace(false)
    public static class ProgramAttach extends Event {
        @Label("Program Name")
        public String programName;

        @Label("Section")
        public String section;
    }

    /**
     * Fired when a BPF entry point is detached.
     */
    @Name("me.bechberger.ebpf.ProgramDetach")
    @Label("BPF Program Detach")
    @Category({"BPF"})
    @Description("A BPF program entry point was detached from its hook.")
    @StackTrace(false)
    public static class ProgramDetach extends Event {
        @Label("Program Name")
        public String programName;
    }

    /**
     * Fired on every map-put operation from Java-side code.
     *
     * <p>High-frequency on busy maps; keep disabled unless profiling map writes.
     */
    @Name("me.bechberger.ebpf.MapPut")
    @Label("BPF Map Put")
    @Category({"BPF", "Maps"})
    @Description("A value was written into a BPF map from Java.")
    @StackTrace(false)
    @Threshold("100 ms")
    public static class MapPut extends Event {
        @Label("Map Name")
        public String mapName;

        @Label("Key")
        public String key;
    }

    /**
     * Fired on every map-get operation from Java-side code.
     *
     * <p>High-frequency on busy maps; keep disabled unless profiling map reads.
     */
    @Name("me.bechberger.ebpf.MapGet")
    @Label("BPF Map Get")
    @Category({"BPF", "Maps"})
    @Description("A value was read from a BPF map from Java.")
    @StackTrace(false)
    @Threshold("100 ms")
    public static class MapGet extends Event {
        @Label("Map Name")
        public String mapName;

        @Label("Key")
        public String key;

        @Label("Found")
        public boolean found;
    }
}
