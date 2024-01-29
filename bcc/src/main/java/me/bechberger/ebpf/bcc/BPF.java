package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.LibraryLoader;
import me.bechberger.ebpf.bcc.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static me.bechberger.ebpf.bcc.PanamaUtil.*;

/**
 * Main class for BPF functionality, modelled after the BPF class from the bcc Python bindings
 */
public class BPF implements AutoCloseable {

    static {
        LibraryLoader.load();
    }

    /**
     * Construct a BPF object fluently
     */
    public static class BCCBuilder {

        private String text;
        private String fileName = "";
        private Path hdrFile;
        private boolean allowRLimit = true;
        private int debug;


        private BCCBuilder() {
        }

        public BCCBuilder withText(String text) {
            this.text = text;
            this.fileName = "<text>";
            return this;
        }

        public BCCBuilder withFile(Path srcFile) throws IOException {
            this.text = Files.readString(srcFile);
            this.fileName = srcFile.toString();
            return this;
        }

        public BCCBuilder withHdrFile(Path hdrFile) {
            if (hdrFile != null && !Files.exists(hdrFile))
                throw new IllegalArgumentException("Header file does not exist: " + hdrFile);
            this.hdrFile = hdrFile;
            return this;
        }

        public BCCBuilder prohibitRLimit() {
            this.allowRLimit = false;
            return this;
        }

        public BCCBuilder withDebug(int debug) {
            this.debug = debug;
            return this;
        }

        public BPF build() {
            BPF bpf = new BPF(text, fileName, hdrFile, allowRLimit, debug);
            bpf.registerCleanup();
            return bpf;
        }
    }

    /**
     * Prefixes for system calls on different supported platforms (but the Java bindings are only tested on x86_64)
     */
    private static final List<String> syscallPrefixes = List.of("sys_", "__x64_sys_", "__x32_compat_sys_",
            "__ia32_compat_sys_", "__arm64_sys_", "__s390x_sys_", "__s390_sys_");

    /** Arena that lives as long as this object */
    private final Arena arena = Arena.ofConfined();

    /**
     * eBPF program text
     */
    private final String text;

    /**
     * debug flags
     */
    private final int debug;

    private MemorySegment module;

    /**
     * Disable the clean-up on close?
     */
    private boolean disableCleanup = false;
    private static final Map<Integer, SymbolCache> _sym_caches = new HashMap<>();

    /**
     * eBPF program function name -> function
     */
    private final Map<String, BPFFunction> funcs = new HashMap<>();
    private final Map<String, BPFTable<?, ?>> tables = new HashMap<>();

    private static final int DEFAULT_PROBE_LIMIT = 1000;
    private static int _num_open_probes = 0;

    /**
     * event name -> function name -> file descriptor
     */
    private final Map<String, Map<String, Integer>> kprobe_fds = new HashMap<>();

    private LineReader traceFile = null;

    private final Map<BPFTable.PerfEventArray.PerfEventArrayId, MemorySegment> perfBuffers = new HashMap<>();

    private final Map<String, Integer> raw_tracepoint_fds = new HashMap<>();

    /**
     * Construct a BPF object from a string
     * <p>
     * Call registerCleanup afterwards
     */
    private BPF(String text, String fileName, @Nullable Path hdrFile, boolean allowRLimit, int debug) {
        this.text = text;
        MemorySegment textNative = arena.allocateUtf8String(text);
        this.debug = debug;

        /*
                self.module = lib.bpf_module_create_c_from_string(text,
                                                          self.debug,
                                                          cflags_array, len(cflags_array),
                                                          allow_rlimit, device)
         */
        var maybeModule = bpf_module_create_c_from_string(arena, textNative, debug, MemorySegment.NULL, 0, allowRLimit ? 1 : 0, MemorySegment.NULL);
        if (maybeModule.err() != 0 && maybeModule.err() != 2) {
           throw new BPFCallException(STR."Failed to compile BPF module: \{PanamaUtil.errnoString(maybeModule.err())}");
        }
        if (maybeModule.err() != 0) {
            System.err.println(STR."Warning BPF constructor: \{fileName} \{maybeModule.err()} \{PanamaUtil.errnoString(maybeModule.err())}");
        }
        module = maybeModule.result();

        if (module == null) throw new RuntimeException(STR."Failed to compile BPF module \{fileName}");

        trace_autoload();
    }

    // error checked version of Lib.bpf_module_create_c_from_string
    private static HandlerWithErrno<MemorySegment> BPF_MODULE_CREATE_C_FROM_STRING = new HandlerWithErrno<>("bpf_module_create_c_from_string",
            FunctionDescriptor.of(ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    JAVA_INT,
                    ValueLayout.ADDRESS
            ));

    private static ResultAndErr<MemorySegment> bpf_module_create_c_from_string(Arena arena, MemorySegment text, int debug, MemorySegment cflags, int cflagsLen,
                                                                               int allowRLimit, MemorySegment device) {
        return BPF_MODULE_CREATE_C_FROM_STRING.call(arena, text, debug, cflags, cflagsLen, allowRLimit, device);
    }

    public static BCCBuilder builder(String text) {
        return new BCCBuilder().withText(text);
    }

    public static BCCBuilder builder(Path srcFile) throws IOException {
        return new BCCBuilder().withFile(srcFile);
    }

    private void registerCleanup() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
    }

    /**
     * Loaded ebpf function
     */
    public record BPFFunction(BPF BPF, String name, int fd) {
    }

    /**
     * Returns the arena that lives as long as this object
     */
    public Arena arena() {
        return arena;
    }

    /**
     * Does the BPF program contain a the given function?
     * <p/>
     * Uses a regex to find the function, so it my be failing.
     *
     * @param name name of the function
     */
    public boolean doesFunctionExistInText(String name) {
        return Pattern.compile(STR." \{name}\\(.*\\).*\\{").matcher(text).find();
    }

    private static HandlerWithErrno<Integer> BCC_FUNC_LOAD = new HandlerWithErrno<>("bcc_func_load",
            FunctionDescriptor.of(JAVA_INT,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    ValueLayout.ADDRESS,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    JAVA_INT,
                    ValueLayout.ADDRESS,
                    JAVA_INT,
                    ValueLayout.ADDRESS,
                    JAVA_INT
            ));

    private static ResultAndErr<Integer> bcc_func_load(Arena arena, MemorySegment module, int prog_type, MemorySegment funcNameNative,
                                                       MemorySegment funcStart, int funcSize, MemorySegment license, int kernVersion,
                                                       int logLevel, MemorySegment logBuf, int logSize, MemorySegment device, int attachType) {
        return BCC_FUNC_LOAD.call(arena, module, prog_type, funcNameNative, funcStart, funcSize, license, kernVersion,
                logLevel, logBuf, logSize, device, attachType);
    }

    /**
     * Load a function into the BPF module
     *
     * @param func_name name of the function to load
     * @param prog_type type of the program (Lib.BPF_PROG_TYPE_*)
     */
    public BPFFunction load_func(String func_name, int prog_type, MemorySegment device, int attach_type) {
        if (funcs.containsKey(func_name)) return funcs.get(func_name);
        if (!doesFunctionExistInText(func_name))
            throw new RuntimeException(STR."Trying to use undefined function \{func_name}");
        try (var arena = Arena.ofConfined()) {
            MemorySegment funcNameNative = arena.allocateUtf8String(func_name);
            if (Lib.bpf_function_start(module, funcNameNative) == null)
                throw new RuntimeException(STR."Unknown program \{func_name}");
            int log_level = 0;
            if ((debug & LogLevel.DEBUG_BPF_REGISTER_STATE) != 0) {
                log_level = 2;
            } else if ((debug & LogLevel.DEBUG_BPF) != 0) {
                log_level = 1;
            }
            try {
                var res = bcc_func_load(arena, module, prog_type, funcNameNative,
                        Lib.bpf_function_start(module, funcNameNative),
                        (int) Lib.bpf_function_size(module, funcNameNative),
                        Lib.bpf_module_license(module), Lib.bpf_module_kern_version(module),
                        log_level, MemorySegment.NULL, 0, device, attach_type);
                if (res.result() < 0) {
                    disableCleanup = true;
                    if (res.err() == PanamaUtil.ERRNO_PERM_ERROR)
                        throw new BPFCallException("Need to run with root priviledges to load BPF functions, bcc_load_func failed", res.err());
                    throw new BPFCallException(STR."Failed to load BPF function \{func_name}", res.err());
                }
                var fn = new BPFFunction(this, func_name, res.result());
                funcs.put(func_name, fn);
                return fn;
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Load a function into the BPF module
     *
     * @param func_name name of the function to load
     * @param prog_type type of the program (Lib.BPF_PROG_TYPE_*)
     */
    public BPFFunction load_func(String func_name, int prog_type) {
        return load_func(func_name, prog_type, MemorySegment.NULL, -1);
    }

    public BPFFunction load_raw_tracepoint_func(String func_name) {
        return load_func(func_name, Lib.BPF_PROG_TYPE_RAW_TRACEPOINT());
    }

    MemorySegment dump_func(Arena arena, String func_name) {
        var funcNameNative = arena.allocateUtf8String(func_name);
        if (Lib.bpf_function_start(module, funcNameNative) == null)
            throw new RuntimeException(STR."Unknown program \{func_name}");
        var start = Lib.bpf_function_start(module, funcNameNative);
        var size = Lib.bpf_function_size(module, funcNameNative);
        return start.asSlice(0, size);
    }

    public String disassemble_func(String func_name) {
        try (var arena = Arena.ofConfined()) {
            var bpfstr = dump_func(arena, func_name);
            return Disassembler.disassemble_prog(func_name, bpfstr);
        }
    }

    /**
     * Return the eBPF bytecodes for the specified function
     */
    // incomplete
    private void trace_autoload() {
        for (int i = 0; i < Lib.bpf_num_functions(module); i++) {
            var funcName = PanamaUtil.toString(Lib.bpf_function_name(module, i));
            assert funcName != null;
            if (funcName.startsWith("kprobe__")) {
                var fn = load_func(funcName, Lib.BPF_PROG_TYPE_KPROBE());
                attach_kprobe(fix_syscall_fnname(funcName.substring(8)), 0, fn.name, null);
            } else if (funcName.startsWith("tracepoint__")) {
                var fn = load_func(funcName, Lib.BPF_PROG_TYPE_TRACEPOINT());
                var tp = funcName.substring("tracepoint__".length()).replace("__", ":");
                attach_raw_tracepoint(tp, fn.name);
            }
        }
    }

    public record TraceFields(String line, String task, int pid, String cpu, String flags, double ts, String msg) {
        public String format(String fmt) {
            String fields = fmt;
            fields = fields.replace("{0}", task);
            fields = fields.replace("{1}", String.valueOf(pid));
            fields = fields.replace("{2}", cpu);
            fields = fields.replace("{3}", flags);
            fields = fields.replace("{4}", String.valueOf(ts));
            fields = fields.replace("{5}", msg);
            return fields;
        }
    }

    /**
     * Open the trace_pipe if not already open
     * <p/>
     * Currently, doesn't support non-blocking mode
     */
    public LineReader trace_open() {
        /*    def trace_open(self, nonblocking=False):
        """trace_open(nonblocking=False)

        Open the trace_pipe if not already open
        """
        if not self.tracefile:
            self.tracefile = open("%s/trace_pipe" % TRACEFS, "rb")
            if nonblocking:
                fd = self.tracefile.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return self.tracefile*/
        if (traceFile == null) {
            try {
                var p = Constants.TRACEFS.resolve("trace_pipe");
                traceFile = new LineReader(p);
            } catch (IOException e) {
                throw new RuntimeException("Failed to open trace_pipe");
            }
        }
        return traceFile;
    }

    /**
     * Read from the kernel debug trace pipe and return the fields.
     * Returns null if no line was read.
     * <p/>
     * Currently, doesn't support non-blocking mode
     */
    public TraceFields trace_fields() {
        while (true) {
            String tracedLine = trace_readline();
            if (tracedLine == null) return null;
            // don't print messages related to lost events
            if (tracedLine.startsWith("CPU:")) continue;
            try {
                var task = tracedLine.substring(0, 16).strip();
                var line = tracedLine.substring(17);
                var tsEnd = line.indexOf(":");
                var pidCpuFlagsTs = line.substring(0, tsEnd).split(" +");
                var pid = Integer.parseInt(pidCpuFlagsTs[0]);
                var cpu = pidCpuFlagsTs[1].substring(1, pidCpuFlagsTs[1].length() - 1);
                var flags = pidCpuFlagsTs[2];
                var ts = Double.parseDouble(pidCpuFlagsTs[3]);
                // line[ts_end:] will have ": [sym_or_addr]: msgs"
                // For trace_pipe debug output, the addr typically
                // is invalid (e.g., 0x1). For kernel 4.12 or earlier,
                // if address is not able to match a kernel symbol,
                // nothing will be printed out. For kernel 4.13 and later,
                // however, the illegal address will be printed out.
                // Hence, both cases are handled here.
                line = line.substring(tsEnd + 1);
                int symEnd = line.indexOf(":");
                var msg = line.substring(symEnd + 2);
                return new TraceFields(tracedLine, task, pid, cpu, flags, ts, msg);
            } catch (NumberFormatException e) {
                return new TraceFields(tracedLine, "Unknown", 0, "Unknown", "Unknown", 0.0, "Unknown");
            }
        }
    }

    /**
     * Read from the kernel debug trace pipe and return one line
     */
    public String trace_readline() {
        return trace_open().readLine();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * If fmt is specified, apply as a format string to the output.
     * Skip messages if format returns null.
     *
     * @param format format function
     *
     * Example:
     * {@snippet :
     *    b.trace_print(t -> t.msg()) // print only the message
     * }
     */
    public void trace_print(@Nullable Function<TraceFields, @Nullable String> format) {
        while (true) {
            String line;
            if (format != null) {
                var fields = trace_fields();
                if (fields == null) continue;
                line = format.apply(fields);
                if (line == null) continue;
            } else {
                line = trace_readline();
                if (line == null) continue;
            }
            System.out.println(line);
            System.out.flush();
        }
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * If fmt is specified, apply as a format string to the output. See
     * trace_fields for the members of the tuple
     * example: trace_print(fmt="pid {1}, msg = {5}")
     * <p/>
     * The format string is not as expressive as in Python, therefore, please use
     * the {@link #trace_print(Function)} method if you need more flexibility.
     *
     * @param fmt format string
     */
    public void trace_print(String fmt) {
        if (fmt != null) {
            trace_print(fields -> fields.format(fmt));
            return;
        }
        trace_print((Function<TraceFields, String>) null);
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     */
    public void trace_print() {
        trace_print((String) null);
    }

    /**
     * Given a Kernel function name that represents a syscall but already has a
     * prefix included, transform it to current system's prefix. For example,
     * if "sys_clone" provided, the helper may translate it to "__x64_sys_clone".
     */
    private String fix_syscall_fnname(String fnName) {
        for (var prefix : syscallPrefixes) {
            if (fnName.startsWith(prefix)) {
                return get_syscall_fnname(fnName.substring(prefix.length()));
            }
        }
        return fnName;
    }

    public static boolean support_raw_tracepoint() {
        return BPF.ksymname("bpf_find_raw_tracepoint") != -1 ||
                BPF.ksymname("bpf_get_raw_tracepoint") != -1;
    }

    public static boolean support_raw_tracepoint_in_module() {
        var kallsyms = Path.of("/proc/kallsyms");
        try {
            return Files.lines(kallsyms).anyMatch(line -> {
                var parts = line.trim().split(" ");
                var name = parts[2].split("\t")[0];
                return name.equals("bpf_trace_modules");
            });
        } catch (IOException e) {
            throw new RuntimeException("Failed to read /proc/kallsyms", e);
        }
    }

    public static boolean kernel_struct_has_field(String structName, String fieldName) {
        try (var arena = Arena.ofConfined()) {
            var structNameNative = arena.allocateUtf8String(structName);
            var fieldNameNative = arena.allocateUtf8String(fieldName);
            return Lib.kernel_struct_has_field(structNameNative, fieldNameNative) == 1;
        }
    }

    /**
     * Attach a function to a raw tracepoint
     * <p>
     * Run the bpf function denoted by fn_name every time the kernel tracepoint
     * specified by 'tp' is hit. The bpf function should be loaded as a
     * RAW_TRACEPOINT type. The fn_name is the kernel tracepoint name,
     * e.g., sched_switch, sys_enter_bind, etc.
     * <p>
     * Examples:
     * {@snippet :
     *  bpf.attach_raw_tracepoint("sched_switch", "on_switch")
     * }
     */
    public BPF attach_raw_tracepoint(@Nullable String tracepoint, @Nullable String fn_name) {
        try (var arena = Arena.ofConfined()) {
            if (tracepoint == null || fn_name == null) return this;
            if (raw_tracepoint_fds.containsKey(tracepoint))
                throw new RuntimeException(STR."Raw tracepoint \{tracepoint} has been attached");
            var fn = load_func(fn_name, Lib.BPF_PROG_TYPE_RAW_TRACEPOINT());
            int fd = Lib.bpf_attach_raw_tracepoint(fn.fd, arena.allocateUtf8String(tracepoint));
            if (fd < 0) throw new RuntimeException("Failed to attach BPF to raw tracepoint");
            raw_tracepoint_fds.put(tracepoint, fd);
            return this;
        }
    }

    /**
     * Attach a function to a raw tracepoint
     * <p>
     * Stop running the bpf function that is attached to the kernel tracepoint
     * specified by 'tp'.
     * <p>
     * Example: {@snippet : bpf.detach_raw_tracepoint("sched_switch")}
     */
    public void detach_raw_tracepoint(@Nullable String tracepoint) {
        if (tracepoint == null) return;
        if (!raw_tracepoint_fds.containsKey(tracepoint))
            throw new RuntimeException(STR."Raw tracepoint \{tracepoint} is not attached");
        Lib.close(raw_tracepoint_fds.get(tracepoint));
        raw_tracepoint_fds.remove(tracepoint);
    }

    public static class FailedToAttachException extends RuntimeException {
        public FailedToAttachException(String message) {
            super(message);
        }
    }

    /**
     * Attach a function to a kprobe
     *
     * @param event     name of the event to attach to
     * @param event_off event offset, can be 0
     * @param fn_name   name of the function to attach
     * @param event_re  event regex, can be null
     */
    public BPF attach_kprobe(@Nullable String event, int event_off, @Nullable String fn_name, @Nullable String event_re) {
        if (event_re != null) {
            var matches = get_kprobe_functions(event_re);
            _check_probe_quota(matches.size());
            int failed = 0;
            var probes = new ArrayList<String>();
            for (var line : matches) {
                try {
                    attach_kprobe(line, 0, fn_name, null);
                } catch (FailedToAttachException e) {
                    failed++;
                    probes.add(line);
                }
            }
            if (failed == matches.size()) {
                var probesStr = String.join("/", probes);
                throw new FailedToAttachException(STR."Failed to attach BPF program \{fn_name} to kprobe \{probesStr}" +
                        "it's not traceable (either non-existing, inlined, or marked as \"notrace\")");
            }
            return this;
        }
        _check_probe_quota(1);
        var fn = load_func(fn_name, Lib.BPF_PROG_TYPE_KPROBE());
        assert event != null;
        var ev_name = STR."p_\{event.replace("+", "_").replace(".", "_")}";
        int fd;
        try (var arena = Arena.ofConfined()) {
            var evNameNative = arena.allocateUtf8String(ev_name);
            var eventNative = arena.allocateUtf8String(event);
            fd = Lib.bpf_attach_kprobe(fn.fd, 0, evNameNative, eventNative, event_off, 0);
        }
        if (fd < 0) {
            throw new FailedToAttachException(STR."Failed to attach BPF program \{fn_name} to kprobe \{event}," +
                    "it's not traceable (either non-existing, inlined, or marked as \"notrace\")");
        }
        _add_kprobe_fd(ev_name, fn_name, fd);
        return this;
    }

    /**
     * Attach a function to a kprobe
     */
    public void attach_kprobe(String event, String fn_name) {
        attach_kprobe(event, 0, fn_name, null);
    }

    private void detach_kprobe_event(String ev_name) {
        var fnNames = new ArrayList<>(kprobe_fds.get(ev_name).keySet());
        for (var fnName : fnNames) {
            detach_kprobe_event_by_fn(ev_name, fnName);
        }
    }

    private void detach_kprobe_event_by_fn(String ev_name, String fn_name) {
        if (!kprobe_fds.containsKey(ev_name)) throw new RuntimeException(STR."Kprobe \{ev_name} is not attached");
        var res = Lib.bpf_close_perf_event_fd(kprobe_fds.get(ev_name).get(fn_name));
        if (res < 0) throw new RuntimeException("Failed to close kprobe FD");
        _del_kprobe_fd(ev_name, fn_name);
        if (kprobe_fds.get(ev_name).isEmpty()) {
            try (var arena = Arena.ofConfined()) {
                var evNameNative = arena.allocateUtf8String(ev_name);
                res = Lib.bpf_detach_kprobe(evNameNative);
            }
            if (res < 0) throw new RuntimeException("Failed to detach BPF from kprobe");
        }
    }

    /**
     * get table without caching
     */
    public <T extends BPFTable<?, ?>> T get_table(String name, BPFTable.TableProvider<? extends T> provider) {
        try (var arena = Arena.ofConfined()) {
            var nameNative = arena.allocateUtf8String(name);
            var mapId = Lib.bpf_table_id(module, nameNative);
            var mapFd = Lib.bpf_table_fd(module, nameNative);
            if (mapFd < 0) throw new RuntimeException(STR."Failed to load BPF Table \{name}");
            // TODO: error checking
            return provider.createTable(this, mapId, mapFd, name);
        }
    }


    /**
     * get a map
     */
    @SuppressWarnings("unchecked")
    public <T extends BPFTable<?, ?>> T get(String name, BPFTable.TableProvider<? extends T> provider) {
        return (T) tables.computeIfAbsent(name, k -> get_table(name, provider));
    }

    /**
     * Number of maps allocated
     */
    public int size() {
        return tables.size();
    }

    /**
     * Remove map from cache
     */
    public boolean remove(String name) {
        var table = tables.remove(name);
        if (table == null) return false;
        return true;
    }

    /**
     * names of the maps
     */
    public Iterable<String> keys() {
        return tables.keySet();
    }

    /**
     * Get allow available kprobe functions that aren't blacklisted
     *
     * @param event_re regex to match the functions against
     * @return list of function names
     */
    public static List<String> get_kprobe_functions(String event_re) {
        /*
        blacklist_file = "%s/kprobes/blacklist" % DEBUGFS
        try:
            with open(blacklist_file, "rb") as blacklist_f:
                blacklist = set([line.rstrip().split()[1] for line in blacklist_f])
        except IOError as e:
            if e.errno != errno.EPERM:
                raise e
            blacklist = set([])*/
        var blacklist_file = Constants.DEBUGFS.resolve("kprobes").resolve("blacklist");
        Set<String> blacklist;
        try {
            blacklist = Files.readAllLines(blacklist_file).stream()
                    .map(line -> line.trim().split(" ")[1]).collect(Collectors.toSet());
        } catch (IOException e) {
            if (e.getMessage().toLowerCase().contains("permission denied"))
                throw new RuntimeException("Permission denied", e);
            blacklist = Set.of();
        }
        /*
        avail_filter_file = "%s/tracing/available_filter_functions" % DEBUGFS
        try:
            with open(avail_filter_file, "rb") as avail_filter_f:
                avail_filter = set([line.rstrip().split()[0] for line in avail_filter_f])
        except IOError as e:
            if e.errno != errno.EPERM:
                raise e
            avail_filter = set([])*/
        var availFilterFile = Constants.TRACEFS.resolve("available_filter_functions");
        Set<String> availFilter;
        try {
            availFilter = Files.readAllLines(availFilterFile).stream()
                    .map(line -> line.trim().split(" ")[0]).collect(Collectors.toSet());
        } catch (IOException e) {
            if (e.getMessage().toLowerCase().contains("permission denied"))
                throw new RuntimeException("Permission denied", e);
            availFilter = Set.of();
        }
        /* fns = []

        in_init_section = 0
        in_irq_section = 0
        with open("/proc/kallsyms", "rb") as avail_file:
            for line in avail_file:
            # ...
        return set(fns)     # Some functions may appear more than once*/
        var fns = new HashSet<String>();
        var inInitSection = 0;
        var inIrqSection = 0;
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of("/proc/kallsyms"));
        } catch (IOException e) {
            throw new RuntimeException("Failed to read /proc/kallsyms", e);
        }
        for (String line : lines) {
            /* (t, fn) = line.rstrip().split()[1:3]
                # Skip all functions defined between __init_begin and
                # __init_end
                if in_init_section == 0:
                    if fn == b'__init_begin':
                        in_init_section = 1
                        continue
                elif in_init_section == 1:
                    if fn == b'__init_end':
                        in_init_section = 2
                    continue*/
            var parts = line.trim().split(" ");
            var t = parts[1];
            var fn = parts[2];
            // Skip all functions defined between __init_begin and __init_end
            if (inInitSection == 0) {
                if (fn.equals("__init_begin")) {
                    inInitSection = 1;
                    continue;
                }
            } else if (inInitSection == 1) {
                if (fn.equals("__init_end")) {
                    inInitSection = 2;
                }
                continue;
            }
            /* # Skip all functions defined between __irqentry_text_start and
                # __irqentry_text_end
                if in_irq_section == 0:
                    if fn == b'__irqentry_text_start':
                        in_irq_section = 1
                        continue
                    # __irqentry_text_end is not always after
                    # __irqentry_text_start. But only happens when
                    # no functions between two irqentry_text
                    elif fn == b'__irqentry_text_end':
                        in_irq_section = 2
                        continue
                elif in_irq_section == 1:
                    if fn == b'__irqentry_text_end':
                        in_irq_section = 2
                    continue*/
            // Skip all functions defined between __irqentry_text_start and __irqentry_text_end
            if (inIrqSection == 0) {
                if (fn.equals("__irqentry_text_start")) {
                    inIrqSection = 1;
                    continue;
                }
                // __irqentry_text_end is not always after __irqentry_text_start.
                // But only happens when no functions between two irqentry_text
                else if (fn.equals("__irqentry_text_end")) {
                    inIrqSection = 2;
                    continue;
                }
            } else if (inIrqSection == 1) {
                if (fn.equals("__irqentry_text_end")) {
                    inIrqSection = 2;
                }
                continue;
            }
            /*
            # All functions defined as NOKPROBE_SYMBOL() start with the
                # prefix _kbl_addr_*, blacklisting them by looking at the name
                # allows to catch also those symbols that are defined in kernel
                # modules.
                if fn.startswith(b'_kbl_addr_'):
                    continue
                # Explicitly blacklist perf-related functions, they are all
                # non-attachable.
                elif fn.startswith(b'__perf') or fn.startswith(b'perf_'):
                    continue
                # Exclude all static functions with prefix __SCT__, they are
                # all non-attachable
                elif fn.startswith(b'__SCT__'):
                    continue
                # Exclude all gcc 8's extra .cold functions
                elif re.match(b'^.*\.cold(\.\d+)?$', fn):
                    continue
                if (t.lower() in [b't', b'w']) and re.fullmatch(event_re, fn) \
                    and fn not in blacklist \
                    and fn in avail_filter:
                    fns.append(fn)
             */
            // All functions defined as NOKPROBE_SYMBOL() start with the prefix _kbl_addr_*,
            // blacklisting them by looking at the name allows to catch also those symbols that are defined in kernel modules.
            if (fn.startsWith("_kbl_addr_")) {
                continue;
            }
            // Explicitly blacklist perf-related functions, they are all non-attachable.
            else if (fn.startsWith("__perf") || fn.startsWith("perf_")) {
                continue;
            }
            // Exclude all static functions with prefix __SCT__, they are all non-attachable
            else if (fn.startsWith("__SCT__")) {
                continue;
            }
            // Exclude all gcc 8's extra .cold functions
            else if (fn.matches("^.*\\.cold(\\.\\d+)?$")) {
                continue;
            }
            if ((t.equalsIgnoreCase("t") || t.equalsIgnoreCase("w")) &&
                    fn.matches(event_re) && !blacklist.contains(fn) && availFilter.contains(fn)) {
                fns.add(fn);
            }
        }
        return new ArrayList<>(fns);
    }

    private void _check_probe_quota(int num_new_probes) {
        if (_num_open_probes + num_new_probes > get_probe_limit()) {
            throw new RuntimeException("Number of open probes would exceed global quota");
        }
    }

    private static int get_probe_limit() {
        var envProbeLimit = System.getenv("BCC_PROBE_LIMIT");
        if (envProbeLimit != null && envProbeLimit.matches("\\d+")) {
            return Integer.parseInt(envProbeLimit);
        } else {
            return DEFAULT_PROBE_LIMIT;
        }
    }

    private void _add_kprobe_fd(String ev_name, String fn_name, int fd) {
        kprobe_fds.computeIfAbsent(ev_name, k -> new HashMap<>()).put(fn_name, fd);
        _num_open_probes++;
    }

    private void _del_kprobe_fd(String ev_name, String fn_name) {
        kprobe_fds.get(ev_name).remove(fn_name);
        _num_open_probes--;
    }

    /**
     * Given a syscall's name, return the full Kernel function name with current
     * system's syscall prefix. For example, given "clone" the helper would
     * return "sys_clone" or "__x64_sys_clone".
     */
    public String get_syscall_fnname(String fnName) {
        return get_syscall_prefix() + fnName;
    }

    /**
     * Find current system's syscall prefix by testing on the BPF syscall.
     * If no valid value found, will return the first possible value which
     * would probably lead to error in later API calls.
     */
    private String get_syscall_prefix() {
        for (var prefix : syscallPrefixes) {
            if (ksymname(STR."\{prefix}bpf") != -1) {
                return prefix;
            }
        }
        return syscallPrefixes.getFirst();
    }


    // incomplete
    private void cleanup() {
        if (disableCleanup) return;
        disableCleanup = true;
        for (var k : kprobe_fds.keySet()) {
            detach_kprobe_event(k);
        }
        for (var k : raw_tracepoint_fds.keySet()) {
            detach_raw_tracepoint(k);
        }
        if (traceFile != null) {
            traceFile.close();
        }
        close_fds();
    }

    /**
     * Closes all associated files descriptors. Attached BPF programs are not
     * detached.
     */
    // complete
    void close_fds() {
        for (var fn : funcs.values()) {
            Lib.close(fn.fd);
        }
        if (module != null) {
            Lib.bpf_module_destroy(module);
            module = null;
        }
    }

    /**
     * Translate a kernel name into an address. This is the reverse of
     * {@link #ksymname(String)}. Returns -1 when the function name is unknown.
     */
    private static long ksymname(String name) {
        return _sym_cache(-1).resolve_name(null, name);
    }

    /**
     * Returns a symbol cache for the specified PID. The kernel symbol cache is
     * accessed by providing any PID less than zero.
     */
    private static SymbolCache _sym_cache(int pid) {
        if (pid < 0 && pid != -1) {
            pid = -1;
        }
        return _sym_caches.computeIfAbsent(pid, SymbolCache::new);
    }

    private int getOpenProbesNum() {
        return _num_open_probes;
    }

    /**
     * Poll from all open perf ring buffers, calling the callback that was
     * provided when calling {@link BPFTable.PerfEventArray#open_perf_buffer(BPFTable.PerfEventArray.EventCallback)} for each entry.
     *
     * Without a timeout.
     */
    public void perf_buffer_poll() {
        perf_buffer_poll(-1);
    }

    /**
     * Poll from all open perf ring buffers, calling the callback that was
     * provided when calling {@link BPFTable.PerfEventArray#open_perf_buffer(BPFTable.PerfEventArray.EventCallback)} for each entry.
     */
    public void perf_buffer_poll(int timeout) {
        try (var arena = Arena.ofConfined()) {
            var readers = arena.allocateArray(PanamaUtil.POINTER, perfBuffers.size());
            int i = 0;
            for (var v : perfBuffers.values()) {
                readers.setAtIndex(POINTER, i++, v);
            }
            Lib.perf_reader_poll(perfBuffers.size(), readers, timeout);
        }
    }

    /**
     * Consume all open perf buffers, regardless of whether or not
     * they currently contain events data. Necessary to catch 'remainder'
     * events when wakeup_events > 1 is set in open_perf_buffer
     */
    public void perf_buffer_consume() {
        try (var arena = Arena.ofConfined()) {
            var readers = arena.allocateArray(PanamaUtil.POINTER, perfBuffers.size());
            int i = 0;
            for (var v : perfBuffers.values()) {
                readers.setAtIndex(POINTER, i++, v);
            }
            Lib.perf_reader_consume(perfBuffers.size(), readers);
        }
    }

    @Override
    public void close() {
        arena.close();
        cleanup();
    }

    public MemorySegment getModule() {
        return module;
    }

    public void setPerfBuffer(BPFTable.PerfEventArray.PerfEventArrayId id, MemorySegment reader) {
        perfBuffers.put(id, reader);
    }

    public void removePerfBuffer(BPFTable.PerfEventArray.PerfEventArrayId id) {
        perfBuffers.remove(id);
    }

    public boolean hasPerfBuffer(BPFTable.PerfEventArray.PerfEventArrayId id) {
        return perfBuffers.containsKey(id);
    }

    public MemorySegment getPerfBuffer(BPFTable.PerfEventArray.PerfEventArrayId id) {
        return perfBuffers.get(id);
    }
}
