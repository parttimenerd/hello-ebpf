package me.bechberger.ebpf.samples;

import net.fornwall.jelf.ElfFile;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.ElfSymbolTableSection;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Translates raw instruction pointers (from BPF stack-trace maps) into
 * human-readable symbol strings.
 *
 * <p>Two symbol sources are supported:
 * <ul>
 *   <li><b>Kernel</b>: {@code /proc/kallsyms} — loaded once and binary-searched.</li>
 *   <li><b>User-space</b>: ELF {@code .dynsym}/{@code .symtab} via
 *       <a href="https://github.com/fornwall/jelf">jelf</a>, with address-space
 *       layout from {@code /proc/PID/maps}.</li>
 * </ul>
 *
 * <p>All state (kallsyms array, ELF cache) lives in a single instance so callers
 * can share one symbolizer across multiple PIDs and stacks.
 *
 * @see <a href="https://man7.org/linux/man-pages/man2/perf_event_open.2.html">perf_event_open(2)</a>
 * @see <a href="https://docs.kernel.org/bpf/map_stack_trace.html">BPF_MAP_TYPE_STACK_TRACE</a>
 */
public class StackSymbolizer {

    // ── User-space symbolization ──────────────────────────────────────────────

    /**
     * One executable mapping from {@code /proc/PID/maps}.
     *
     * <p>Fields correspond to columns in the maps file:
     * <pre>
     *   start-end  perms  fileOffset  dev  inode  path
     * </pre>
     * {@code fileOffset} converts an absolute runtime VA to the file-relative
     * offset stored in ELF symbol tables (shared libraries are mapped at arbitrary
     * virtual addresses).
     *
     * @see <a href="https://man7.org/linux/man-pages/man5/proc.5.html">proc(5) — /proc/pid/maps</a>
     */
    public record MapRange(long start, long end, long fileOffset, String path) {}

    /** Cache of parsed ELF symbol tables, keyed by absolute file path. */
    private final Map<String, ElfSymbols> elfCache = new HashMap<>();

    /**
     * Parses {@code /proc/pid/maps} into a list of named mappings.
     *
     * <p>Anonymous mappings and pseudo-paths like {@code [heap]} are included;
     * they will produce hex-offset output since they have no ELF symbol table.
     *
     * @param pid target process (must be readable by the current user, typically requires root)
     * @return parsed ranges, or an empty list if the file cannot be read
     */
    public static List<MapRange> readMaps(int pid) {
        try {
            var result = new ArrayList<MapRange>();
            for (var line : Files.readAllLines(Path.of("/proc/" + pid + "/maps"))) {
                var parts = line.split("\\s+", 6);
                if (parts.length < 5) continue;
                var addrs  = parts[0].split("-");
                long start = Long.parseUnsignedLong(addrs[0], 16);
                long end   = Long.parseUnsignedLong(addrs[1], 16);
                long off   = Long.parseUnsignedLong(parts[2], 16);
                String p   = parts.length == 6 ? parts[5].trim() : "[anon]";
                if (!p.isEmpty()) result.add(new MapRange(start, end, off, p));
            }
            return result;
        } catch (IOException e) { return List.of(); }
    }

    /**
     * Symbolizes a user-space instruction pointer.
     *
     * <p>Lookup chain:
     * <ol>
     *   <li>Find the {@link MapRange} containing {@code ip}.</li>
     *   <li>Convert to file offset: {@code ip - range.start + range.fileOffset}.</li>
     *   <li>Binary-search the ELF symbol table ({@link ElfSymbols#lookup}).
     *       Returns {@code "libname`symbol+0xoffset"} on success.</li>
     *   <li>If ELF lookup misses, returns {@code "libname+0xfileOffset"}.</li>
     *   <li>If no range covers the address, returns {@code "[unknown]+0xip"}.</li>
     * </ol>
     *
     * <p>The backtick separator ({@code lib`func}) follows the {@code perf}/{@code bpftrace} convention.
     *
     * @param ip     absolute instruction pointer from the BPF stack trace
     * @param ranges mappings for the process, from {@link #readMaps}
     * @return human-readable symbol string, never null
     */
    public String symUser(long ip, List<MapRange> ranges) {
        for (var r : ranges) {
            if (ip >= r.start() && ip < r.end()) {
                long fileOff = ip - r.start() + r.fileOffset();
                String lib   = Path.of(r.path()).getFileName().toString();
                var elf = elfCache.computeIfAbsent(r.path(), ElfSymbols::load);
                String sym = elf.lookup(fileOff);
                if (sym != null) return lib + "`" + sym;
                return lib + "+0x" + Long.toHexString(fileOff);
            }
        }
        return "[unknown]+0x" + Long.toHexString(ip);
    }

    // ── ELF symbol table ──────────────────────────────────────────────────────

    /**
     * Sorted, binary-searchable snapshot of function symbols from one ELF file.
     *
     * <p>Reads {@code .dynsym} (preferred — always present in shared libraries) or
     * {@code .symtab} (full table, often stripped from release builds) using
     * <a href="https://github.com/fornwall/jelf">jelf</a>. Only {@code STT_FUNC} and
     * {@code STT_GNU_IFUNC} (type 10) symbols with non-zero addresses are kept.
     *
     * <p>Symbols are sorted by {@code st_value} for binary search in {@link #lookup}.
     *
     * @see <a href="https://refspecs.linuxfoundation.org/elf/elf.pdf">ELF-64 specification</a>
     */
    static final class ElfSymbols {
        private static final ElfSymbols EMPTY = new ElfSymbols(new long[0], new long[0], new String[0]);

        /** Sorted symbol start addresses ({@code st_value}). */
        private final long[]   addrs;
        /** Symbol sizes ({@code st_size}); 0 means unknown. Parallel to {@link #addrs}. */
        private final long[]   sizes;
        /** Symbol names. Parallel to {@link #addrs}. */
        private final String[] names;

        private ElfSymbols(long[] addrs, long[] sizes, String[] names) {
            this.addrs = addrs; this.sizes = sizes; this.names = names;
        }

        /**
         * Resolves a file offset to {@code "name+0xoffset"}, or {@code null} if no
         * function symbol covers the address.
         *
         * <p>Finds the symbol with the largest {@code st_value ≤ fileOff}, then validates:
         * <ul>
         *   <li>Known size ({@code st_size > 0}): if {@code fileOff} is past the end → {@code null}.</li>
         *   <li>Unknown size ({@code st_size == 0}): if the next symbol also starts before
         *       {@code fileOff}, this symbol has ended → {@code null}.</li>
         * </ul>
         *
         * @param fileOff file-relative address to look up
         * @return symbol string or {@code null}
         */
        String lookup(long fileOff) {
            if (addrs.length == 0) return null;
            int lo = 0, hi = addrs.length - 1, best = -1;
            while (lo <= hi) {
                int mid = (lo + hi) >>> 1;
                if (Long.compareUnsigned(addrs[mid], fileOff) <= 0) { best = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (best < 0) return null;
            long delta = fileOff - addrs[best];
            if (sizes[best] > 0 && delta >= sizes[best]) return null;
            if (sizes[best] == 0 && best + 1 < addrs.length
                    && Long.compareUnsigned(addrs[best + 1], fileOff) <= 0) return null;
            return delta == 0 ? names[best] : names[best] + "+0x" + Long.toHexString(delta);
        }

        /**
         * Loads symbol information from an ELF file, returning {@link #EMPTY} on any error.
         *
         * <p>Only regular files (absolute paths starting with {@code /}) are parsed;
         * pseudo-paths like {@code [vdso]} or {@code [heap]} are skipped immediately.
         *
         * @param path absolute path to the ELF file (from {@code /proc/PID/maps})
         */
        static ElfSymbols load(String path) {
            if (!path.startsWith("/")) return EMPTY;
            try {
                return parse(path);
            } catch (Exception e) {
                return EMPTY;
            }
        }

        private static ElfSymbols parse(String path) throws Exception {
            ElfFile elf = ElfFile.from(new File(path));

            // .dynsym covers exported symbols and is always present in shared libraries.
            // .symtab is the full table but is often stripped in release builds.
            ElfSymbolTableSection symTab = elf.getDynamicSymbolTableSection();
            if (symTab == null) symTab = elf.getSymbolTableSection();
            if (symTab == null) return EMPTY;

            ElfSymbol[] symbols = symTab.symbols;
            var addrList = new ArrayList<Long>(symbols.length);
            var sizeList = new ArrayList<Long>(symbols.length);
            var nameList = new ArrayList<String>(symbols.length);

            for (ElfSymbol sym : symbols) {
                int type = sym.getType();
                if (type != ElfSymbol.STT_FUNC && type != 10 /* STT_GNU_IFUNC */) continue;
                if (sym.st_value == 0) continue;
                String name = sym.getName();
                if (name == null || name.isEmpty()) continue;
                addrList.add(sym.st_value);
                sizeList.add(sym.st_size);
                nameList.add(name);
            }

            int n = addrList.size();
            if (n == 0) return EMPTY;

            long[] av = addrList.stream().mapToLong(Long::longValue).toArray();
            Integer[] idx = new Integer[n];
            for (int i = 0; i < n; i++) idx[i] = i;
            Arrays.sort(idx, Comparator.comparingLong(i -> av[i]));

            long[]   sa = new long[n];
            long[]   ss = new long[n];
            String[] sn = new String[n];
            for (int i = 0; i < n; i++) {
                sa[i] = av[idx[i]];
                ss[i] = sizeList.get(idx[i]);
                sn[i] = nameList.get(idx[i]);
            }
            return new ElfSymbols(sa, ss, sn);
        }
    }

    // ── Kernel symbol resolution ──────────────────────────────────────────────

    /** Sorted kernel symbol addresses loaded from {@code /proc/kallsyms}. */
    private long[]   kallsymsAddrs = null;
    /** Symbol names parallel to {@link #kallsymsAddrs}. */
    private String[] kallsymsNames = null;

    /**
     * Loads and sorts kernel symbols from {@code /proc/kallsyms} on the first call;
     * subsequent calls return immediately.
     *
     * <p>{@code /proc/kallsyms} format:
     * <pre>
     *   &lt;hex-addr&gt;  &lt;type&gt;  &lt;name&gt;  [&lt;module&gt;]
     * </pre>
     * Only text ({@code T/t}) and weak ({@code W/w}) symbols are kept — data symbols
     * would produce misleading matches for instruction pointers.
     *
     * @see <a href="https://man7.org/linux/man-pages/man5/proc.5.html">proc(5)</a>
     */
    private void loadKallsyms() {
        if (kallsymsAddrs != null) return;
        var addrs = new ArrayList<Long>();
        var names = new ArrayList<String>();
        try (var br = new BufferedReader(new FileReader("/proc/kallsyms"))) {
            String line;
            while ((line = br.readLine()) != null) {
                var parts = line.split("\\s+", 3);
                if (parts.length < 3) continue;
                char type = parts[1].charAt(0);
                if (type != 't' && type != 'T' && type != 'w' && type != 'W') continue;
                long addr = Long.parseUnsignedLong(parts[0], 16);
                if (addr == 0) continue;
                addrs.add(addr);
                names.add(parts[2].split("\\s")[0]); // strip optional "[module]" suffix
            }
        } catch (IOException ignored) {}

        int n = addrs.size();
        long[] a = new long[n];
        String[] s = new String[n];
        for (int i = 0; i < n; i++) { a[i] = addrs.get(i); s[i] = names.get(i); }
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++) idx[i] = i;
        Arrays.sort(idx, Comparator.comparingLong(i -> a[i]));
        long[] sa = new long[n]; String[] sn = new String[n];
        for (int i = 0; i < n; i++) { sa[i] = a[idx[i]]; sn[i] = s[idx[i]]; }
        kallsymsAddrs = sa;
        kallsymsNames = sn;
    }

    /**
     * Symbolizes a kernel instruction pointer using {@code /proc/kallsyms}.
     *
     * <p>Binary-searches for the symbol with the largest start address ≤ {@code ip}
     * and returns {@code "name+0xoffset"}. Falls back to {@code "kernel+0xip"} if
     * kallsyms is empty (e.g. {@code kptr_restrict=2}) or no symbol is found.
     *
     * @param ip kernel-space instruction pointer from the BPF stack trace
     * @return human-readable symbol string, never null
     */
    public String symKernel(long ip) {
        loadKallsyms();
        if (kallsymsAddrs.length == 0) return "kernel+0x" + Long.toHexString(ip);
        int lo = 0, hi = kallsymsAddrs.length - 1, best = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (Long.compareUnsigned(kallsymsAddrs[mid], ip) <= 0) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        if (best < 0) return "kernel+0x" + Long.toHexString(ip);
        long offset = ip - kallsymsAddrs[best];
        return kallsymsNames[best] + "+0x" + Long.toHexString(offset);
    }
}
