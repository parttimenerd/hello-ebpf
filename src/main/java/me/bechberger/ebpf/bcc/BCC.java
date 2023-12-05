package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.raw.Lib;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.VarHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * Main class for BPF functionality
 */
public class BCC implements AutoCloseable {

    static {
        try {
            System.loadLibrary("bcc");
        } catch (UnsatisfiedLinkError e) {
            try {
                System.load("/lib/x86_64-linux-gnu/libbcc.so");
            } catch (UnsatisfiedLinkError e2) {
                System.err.println("Failed to load libbcc.so.0, pass the location of the lib folder " +
                        "via -Djava.library.path after you installed it");
                System.exit(1);
            }
        }
    }

    /**
     * BPF constructor
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

        public BCC build() {
            BCC bpf = new BCC(text, fileName, hdrFile, allowRLimit, debug);
            bpf.registerCleanup();
            return bpf;
        }
    }

    /*     _syscall_prefixes = [
        b"sys_",
        b"__x64_sys_",
        b"__x32_compat_sys_",
        b"__ia32_compat_sys_",
        b"__arm64_sys_",
        b"__s390x_sys_",
        b"__s390_sys_",
    ]*/
    private static final List<String> syscallPrefixes = List.of("sys_", "__x64_sys_", "__x32_compat_sys_",
            "__ia32_compat_sys_", "__arm64_sys_", "__s390x_sys_", "__s390_sys_");

    /**
     * debug flags
     */
    private final int debug;

    private MemorySegment module;

    private boolean disableCleanup = false;
    private static final Map<Integer, SymbolCache> _sym_caches = new HashMap<>();

    private final Map<String, BPFFunction> funcs = new HashMap<>();

    private static final int DEFAULT_PROBE_LIMIT = 1000;
    private static int _num_open_probes = 0;

    /**
     * event name -> function name -> file descriptor
     */
    private final Map<String, Map<String, Integer>> kprobe_fds = new HashMap<>();

    private LineReader tracefile = null;


    /**
     * Call registerCleanup afterwards
     */
    private BCC(String text, String fileName, @Nullable Path hdrFile, boolean allowRLimit, int debug) {
        MemorySegment textNative = Arena.global().allocateUtf8String(text);
        this.debug = debug;

        /*
                self.module = lib.bpf_module_create_c_from_string(text,
                                                          self.debug,
                                                          cflags_array, len(cflags_array),
                                                          allow_rlimit, device)
         */
        module = Lib.bpf_module_create_c_from_string(textNative, debug, MemorySegment.NULL, 0, allowRLimit, MemorySegment.NULL);

        if (module == null) throw new RuntimeException(STR. "Failed to compile BPF module \{ fileName }" );

        trace_autoload();
    }

    public static BCCBuilder builder(String text) {
        return new BCCBuilder().withText(text);
    }

    public static BCCBuilder builder(Path srcFile) throws IOException {
        return new BCCBuilder().withFile(srcFile);
    }

    public void registerCleanup() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::cleanup));
    }

    /**
     * Loaded ebpf function
     */
    public record BPFFunction(BCC bcc, String name, int fd) {
    }


    /*    def load_func(self, func_name, prog_type, device = None, attach_type = -1):
        func_name = _assert_is_bytes(func_name)
        if func_name in self.funcs:
            return self.funcs[func_name]
        if not lib.bpf_function_start(self.module, func_name):
            raise Exception("Unknown program %s" % func_name)
        log_level = 0
        if (self.debug & DEBUG_BPF_REGISTER_STATE):
            log_level = 2
        elif (self.debug & DEBUG_BPF):
            log_level = 1
        fd = lib.bcc_func_load(self.module, prog_type, func_name,
                lib.bpf_function_start(self.module, func_name),
                lib.bpf_function_size(self.module, func_name),
                lib.bpf_module_license(self.module),
                lib.bpf_module_kern_version(self.module),
                log_level, None, 0, device, attach_type)

        if fd < 0:
            atexit.register(self.donothing)
            if ct.get_errno() == errno.EPERM:
                raise Exception("Need super-user privileges to run")

            errstr = os.strerror(ct.get_errno())
            raise Exception("Failed to load BPF program %s: %s" %
                            (func_name, errstr))

        fn = BPF.Function(self, func_name, fd)
        self.funcs[func_name] = fn

        return fn*/

    /**
     * Load a function from the BPF module
     *
     * @param func_name name of the function to load
     * @param prog_type type of the program (Lib.BPF_PROG_TYPE_*)
     */
    // complete
    public BPFFunction load_func(String func_name, int prog_type, MemorySegment device, int attach_type) {
        try (var arena = Arena.ofConfined()) {
            if (funcs.containsKey(func_name)) return funcs.get(func_name);
            MemorySegment funcNameNative = arena.allocateUtf8String(func_name);
            if (Lib.bpf_function_start(module, funcNameNative) == null)
                throw new RuntimeException(STR. "Unknown program \{ func_name }" );
            int log_level = 0;
            if ((debug & LogLevel.DEBUG_BPF_REGISTER_STATE) != 0) {
                log_level = 2;
            } else if ((debug & LogLevel.DEBUG_BPF) != 0) {
                log_level = 1;
            }

            // possible blog post: capturing errno with Panama
            StructLayout capturedStateLayout = Linker.Option.captureStateLayout();
            VarHandle errnoHandle = capturedStateLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"));
            Linker.Option ccs = Linker.Option.captureCallState("errno");
            var handler = Linker.nativeLinker().downcallHandle(PanamaUtil.lookup("bcc_func_load"),
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
            ), ccs);
            MemorySegment capturedState = arena.allocate(capturedStateLayout);
            try {
                int fd = (int)handler.invoke(capturedState, module, prog_type, funcNameNative,
                        Lib.bpf_function_start(module, funcNameNative),
                        (int) Lib.bpf_function_size(module, funcNameNative),
                        Lib.bpf_module_license(module), Lib.bpf_module_kern_version(module),
                        log_level, MemorySegment.NULL, 0, device, attach_type);
                int errno = (int) errnoHandle.get(capturedState);
                if (fd < 0) {
                    disableCleanup = true;
                    if (errno == PanamaUtil.ERRNO_PERM_ERROR)
                         throw new RuntimeException(STR."Need super-user privileges to run");
                    var errstr = PanamaUtil.errnoString(errno);
                    throw new RuntimeException(STR. "Failed to load BPF program \{ func_name }: \{ errstr }" );
                }
                var fn = new BPFFunction(this, func_name, fd);
                funcs.put(func_name, fn);
                return fn;
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        }
    }

    public BPFFunction load_func(String func_name, int prog_type) {
        return load_func(func_name, prog_type, MemorySegment.NULL, -1);
    }

    // incomplete
    private void trace_autoload() {
        /*    def _trace_autoload(self):
        for i in range(0, lib.bpf_num_functions(self.module)):
            func_name = lib.bpf_function_name(self.module, i)
            */
        for (int i = 0; i < Lib.bpf_num_functions(module); i++) {
            var funcName = PanamaUtil.toString(Lib.bpf_function_name(module, i));
            if (funcName.startsWith("kprobe__")) {
                /*if func_name.startswith(b"kprobe__"):
                fn = self.load_func(func_name, BPF.KPROBE)
                self.attach_kprobe(
                    event=self.fix_syscall_fnname(func_name[8:]),
                    fn_name=fn.name)*/
                var fn = load_func(funcName, Lib.BPF_PROG_TYPE_KPROBE());
                attach_kprobe(fix_syscall_fnname(funcName.substring(8)), 0, fn.name, null);
            }
        }
    }

    public record TraceFields(String task, int pid, String cpu, String flags, double ts, String msg) {
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
     */
    public LineReader trace_open(boolean nonblocking) {
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
        if (tracefile == null) {
            try {
                var p = Constants.TRACEFS.resolve("trace_pipe");
                tracefile = new LineReader(p);
            } catch (IOException e) {
                throw new RuntimeException(STR."Failed to open trace_pipe");
            }
        }
        return tracefile;
    }

    /**
     * Read from the kernel debug trace pipe and return a tuple of the
     */
    // complete
    public TraceFields trace_fields(boolean nonblocking) {
        /*
    def trace_fields(self, nonblocking=False):
        """trace_fields(nonblocking=False)

        Read from the kernel debug trace pipe and return a tuple of the
        fields (task, pid, cpu, flags, timestamp, msg) or None if no
        line was read (nonblocking=True)
        """
        while True:
            line = self.trace_readline(nonblocking)
            if not line and nonblocking: return (None,) * 6
            # don't print messages related to lost events
            if line.startswith(b"CPU:"): continue
            task = line[:16].lstrip()
            line = line[17:]
            ts_end = line.find(b":")
            try:
                pid, cpu, flags, ts = line[:ts_end].split()
            except Exception as e:
                continue
            cpu = cpu[1:-1]
            # line[ts_end:] will have ": [sym_or_addr]: msgs"
            # For trace_pipe debug output, the addr typically
            # is invalid (e.g., 0x1). For kernel 4.12 or earlier,
            # if address is not able to match a kernel symbol,
            # nothing will be printed out. For kernel 4.13 and later,
            # however, the illegal address will be printed out.
            # Hence, both cases are handled here.
            line = line[ts_end + 1:]
            sym_end = line.find(b":")
            msg = line[sym_end + 2:]
            try:
                return (task, int(pid), int(cpu), flags, float(ts), msg)
            except Exception as e:
                return ("Unknown", 0, 0, "Unknown", 0.0, "Unknown")*/
        while (true) {
            String line = trace_readline(nonblocking);
            if (line == null) return null;
            // don't print messages related to lost events
            if (line.startsWith("CPU:")) continue;
            try {
                var task = line.substring(0, 16).strip();
                line = line.substring(17);
                var tsEnd = line.indexOf(":");
                var pidCpuFlagsTs = line.substring(0, tsEnd).split(" ");
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
                return new TraceFields(task, pid, cpu, flags, ts, msg);
            } catch (NumberFormatException e) {
                return new TraceFields("Unknown", 0, "Unknown", "Unknown", 0.0, "Unknown");
            }
        }
    }

    /**
     * Read from the kernel debug trace pipe and return one line, returns null if no line was read and non-blocking
     */
    public String trace_readline(boolean nonblocking) {
        if (nonblocking) {
            throw new UnsupportedOperationException("Non-blocking trace_readline not implemented");
        }
        return trace_open(nonblocking).readLine();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * If fmt is specified, apply as a format string to the output. See
     * trace_fields for the members of the tuple
     * example: trace_print(fmt="pid {1}, msg = {5}")
     *
     * @param fmt format string
     */
    // complete
    public void trace_print(@Nullable String fmt) {
        /*
    def trace_print(self, fmt=None):
        """trace_print(self, fmt=None)

        Read from the kernel debug trace pipe and print on stdout.
        If fmt is specified, apply as a format string to the output. See
        trace_fields for the members of the tuple
        example: trace_print(fmt="pid {1}, msg = {5}")
        """

        while True:
            if fmt:
                fields = self.trace_fields(nonblocking=False)
                if not fields: continue
                line = fmt.format(*fields)
            else:
                line = self.trace_readline(nonblocking=False)
            print(line)
            sys.stdout.flush()*/
        while (true) {
            String line;
            if (fmt != null) {
                var fields = trace_fields(false);
                if (fields == null) continue;
                line = fields.format(fmt);
            } else {
                line = trace_readline(false);
                if (line == null) continue;
            }
            System.out.println(line);
            System.out.flush();
        }
    }

    public void trace_print() {
        trace_print(null);
    }

    // complete
    private String fix_syscall_fnname(String fnName) {
        /*    # Given a Kernel function name that represents a syscall but already has a
    # prefix included, transform it to current system's prefix. For example,
    # if "sys_clone" provided, the helper may translate it to "__x64_sys_clone".
    def fix_syscall_fnname(self, name):
        name = _assert_is_bytes(name)
        for prefix in self._syscall_prefixes:
            if name.startswith(prefix):
                return self.get_syscall_fnname(name[len(prefix):])
        return name*/

        for (var prefix : syscallPrefixes) {
            if (fnName.startsWith(prefix)) {
                return get_syscall_fnname(fnName.substring(prefix.length()));
            }
        }
        return fnName;
    }

    public static class FailedToAttachException extends RuntimeException {
        public FailedToAttachException(String message) {
            super(message);
        }
    }

    /**
     * Attach a function to a kprobe
     *
     * @param event   name of the event to attach to
     * @param fn_name name of the function to attach
     */
    // complete
    public BCC attach_kprobe(@Nullable String event, int event_off, @Nullable String fn_name, @Nullable String event_re) {
        /*
    def attach_kprobe(self, event=b"", event_off=0, fn_name=b"", event_re=b""):
        event = _assert_is_bytes(event)
        fn_name = _assert_is_bytes(fn_name)
        event_re = _assert_is_bytes(event_re)

        # allow the caller to glob multiple functions together
        if event_re:
            matches = BPF.get_kprobe_functions(event_re)
            self._check_probe_quota(len(matches))
            failed = 0
            probes = []
            for line in matches:
                try:
                    self.attach_kprobe(event=line, fn_name=fn_name)
                except:
                    failed += 1
                    probes.append(line)
            if failed == len(matches):
                raise Exception("Failed to attach BPF program %s to kprobe %s"
                                ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                                (fn_name, '/'.join(probes)))
            return

        self._check_probe_quota(1)
        fn = self.load_func(fn_name, BPF.KPROBE)
        ev_name = b"p_" + event.replace(b"+", b"_").replace(b".", b"_")
        fd = lib.bpf_attach_kprobe(fn.fd, 0, ev_name, event, event_off, 0)
        if fd < 0:
            raise Exception("Failed to attach BPF program %s to kprobe %s"
                            ", it's not traceable (either non-existing, inlined, or marked as \"notrace\")" %
                            (fn_name, event))
        self._add_kprobe_fd(ev_name, fn_name, fd)
        return self*/

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
                throw new FailedToAttachException(STR. "Failed to attach BPF program \{ fn_name } to kprobe \{ probesStr }" +
                        "it's not traceable (either non-existing, inlined, or marked as \"notrace\")" );
            }
            return this;
        }
        _check_probe_quota(1);
        var fn = load_func(fn_name, Lib.BPF_PROG_TYPE_KPROBE());
        var ev_name = STR. "p_\{ event.replace("+", "_").replace(".", "_") }" ;
        int fd;
        try (var arena = Arena.ofConfined()) {
            var evNameNative = arena.allocateUtf8String(ev_name);
            var eventNative = arena.allocateUtf8String(event);
            fd = Lib.bpf_attach_kprobe(fn.fd, 0, evNameNative, eventNative, event_off, 0);
        }
        if (fd < 0) {
            throw new FailedToAttachException(STR. "Failed to attach BPF program \{ fn_name } to kprobe \{ event }," +
                    "it's not traceable (either non-existing, inlined, or marked as \"notrace\")" );
        }
        _add_kprobe_fd(ev_name, fn_name, fd);
        return this;
    }

    /*    def detach_kprobe_event(self, ev_name):
        ev_name = _assert_is_bytes(ev_name)
        fn_names = list(self.kprobe_fds[ev_name].keys())
        for fn_name in fn_names:
            self.detach_kprobe_event_by_fn(ev_name, fn_name)

    def detach_kprobe_event_by_fn(self, ev_name, fn_name):
        ev_name = _assert_is_bytes(ev_name)
        fn_name = _assert_is_bytes(fn_name)
        if ev_name not in self.kprobe_fds:
            raise Exception("Kprobe %s is not attached" % ev_name)
        res = lib.bpf_close_perf_event_fd(self.kprobe_fds[ev_name][fn_name])
        if res < 0:
            raise Exception("Failed to close kprobe FD")
        self._del_kprobe_fd(ev_name, fn_name)
        if len(self.kprobe_fds[ev_name]) == 0:
            res = lib.bpf_detach_kprobe(ev_name)
            if res < 0:
                raise Exception("Failed to detach BPF from kprobe")*/

    // complete
    public void detach_kprobe_event(String ev_name) {
        var fnNames = new ArrayList<>(kprobe_fds.get(ev_name).keySet());
        for (var fnName : fnNames) {
            detach_kprobe_event_by_fn(ev_name, fnName);
        }
    }

    // complete
    private void detach_kprobe_event_by_fn(String ev_name, String fn_name) {
        if (!kprobe_fds.containsKey(ev_name)) throw new RuntimeException(STR. "Kprobe \{ ev_name } is not attached" );
        var res = Lib.bpf_close_perf_event_fd(kprobe_fds.get(ev_name).get(fn_name));
        if (res < 0) throw new RuntimeException(STR."Failed to close kprobe FD");
        _del_kprobe_fd(ev_name, fn_name);
        if (kprobe_fds.get(ev_name).isEmpty()) {
            try (var arena = Arena.ofConfined()) {
                var evNameNative = arena.allocateUtf8String(ev_name);
                res = Lib.bpf_detach_kprobe(evNameNative);
            }
            if (res < 0) throw new RuntimeException(STR."Failed to detach BPF from kprobe");
        }
    }

    // complete
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

    /*
        def _check_probe_quota(self, num_new_probes):
        global _num_open_probes
        if _num_open_probes + num_new_probes > BPF.get_probe_limit():
            raise Exception("Number of open probes would exceed global quota")
     */
    // complete
    private void _check_probe_quota(int num_new_probes) {
        if (_num_open_probes + num_new_probes > get_probe_limit()) {
            throw new RuntimeException("Number of open probes would exceed global quota");
        }
    }

    /*

    @staticmethod
    def get_probe_limit():
        env_probe_limit = os.environ.get('BCC_PROBE_LIMIT')
        if env_probe_limit and env_probe_limit.isdigit():
            return int(env_probe_limit)
        else:
            return _default_probe_limit
     */
    // complete
    private static int get_probe_limit() {
        var envProbeLimit = System.getenv("BCC_PROBE_LIMIT");
        if (envProbeLimit != null && envProbeLimit.matches("\\d+")) {
            return Integer.parseInt(envProbeLimit);
        } else {
            return DEFAULT_PROBE_LIMIT;
        }
    }

    /*    def _add_kprobe_fd(self, ev_name, fn_name, fd):
        global _num_open_probes
        if ev_name not in self.kprobe_fds:
            self.kprobe_fds[ev_name] = {}
        self.kprobe_fds[ev_name][fn_name] = fd
        _num_open_probes += 1*/
    // complete
    private void _add_kprobe_fd(String ev_name, String fn_name, int fd) {
        kprobe_fds.computeIfAbsent(ev_name, k -> new HashMap<>()).put(fn_name, fd);
        _num_open_probes++;
    }

    private void _del_kprobe_fd(String ev_name, String fn_name) {
        kprobe_fds.get(ev_name).remove(fn_name);
        _num_open_probes--;
    }

    // complete
    private String get_syscall_fnname(String fnName) {
        /*     # Given a syscall's name, return the full Kernel function name with current
    # system's syscall prefix. For example, given "clone" the helper would
    # return "sys_clone" or "__x64_sys_clone".
    def get_syscall_fnname(self, name):
        name = _assert_is_bytes(name)
        return self.get_syscall_prefix() + name*/
        return get_syscall_prefix() + fnName;
    }

    // complete
    private String get_syscall_prefix() {
        /*    # Find current system's syscall prefix by testing on the BPF syscall.
    # If no valid value found, will return the first possible value which
    # would probably lead to error in later API calls.
    def get_syscall_prefix(self):
        for prefix in self._syscall_prefixes:
            if self.ksymname(b"%sbpf" % prefix) != -1:
                return prefix
        return self._syscall_prefixes[0]*/
        for (var prefix : syscallPrefixes) {
            if (ksymname(STR. "\{ prefix }bpf" ) != -1) {
                return prefix;
            }
        }
        return syscallPrefixes.get(0);
    }


    // incomplete
    public void cleanup() {
        if (disableCleanup) return;
        disableCleanup = true;
        /*        for k, v in list(self.kprobe_fds.items()):
            self.detach_kprobe_event(k)*/
        for (var k : kprobe_fds.keySet()) {
            detach_kprobe_event(k);
        }
        if (tracefile != null) {
            tracefile.close();
        }
        close_fds();
    }

    /**
     * Closes all associated files descriptors. Attached BPF programs are not
     * detached.
     */
    // complete
    void close_fds() {
/*
        """close(self)

        Closes all associated files descriptors. Attached BPF programs are not
        detached.
        """
        for name, fn in list(self.funcs.items()):
            os.close(fn.fd)
            del self.funcs[name]
        if self.module:
            lib.bpf_module_destroy(self.module)
            self.module = None
 */
        for (var fn : funcs.values()) {
            Lib.close(fn.fd);
        }
        if (module != null) {
            Lib.bpf_module_destroy(module);
            module = null;
        }
    }

    // complete
    private static long ksymname(String name) {
        /*    def ksymname(name):
        """ksymname(name)

        Translate a kernel name into an address. This is the reverse of
        ksym. Returns -1 when the function name is unknown."""
        return BPF._sym_cache(-1).resolve_name(None, name)*/
        return _sym_cache(-1).resolve_name(null, name);
    }

    // complete
    private static SymbolCache _sym_cache(int pid) {
        /*       @staticmethod
    def _sym_cache(pid):
        """_sym_cache(pid)

        Returns a symbol cache for the specified PID.
        The kernel symbol cache is accessed by providing any PID less than zero.
        """
        if pid < 0 and pid != -1:
            pid = -1
        if not pid in BPF._sym_caches:
            BPF._sym_caches[pid] = SymbolCache(pid)
        return BPF._sym_caches[pid]
         */
        if (pid < 0 && pid != -1) {
            pid = -1;
        }
        return _sym_caches.computeIfAbsent(pid, SymbolCache::new);
    }

    public int getOpenProbesNum() {
        return _num_open_probes;
    }

    @Override
    public void close() {
        cleanup();
    }
}
