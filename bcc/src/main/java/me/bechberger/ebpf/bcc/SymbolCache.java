package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.Lib;
import me.bechberger.ebpf.bcc.raw.bcc_symbol;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;

/**
 * Caches the kernel symbols
 * <p>
 * Copied from the bcc Python bindings
 */
public class SymbolCache {

    public static record ResolveResult(String symbol, long offset, String module) {
    }

    private final MemorySegment cache;

    public SymbolCache(int pid) {
        this.cache = Lib.bcc_symcache_new(pid, MemorySegment.NULL);
    }

    /**
     * Return a tuple of the symbol (function), its offset from the beginning
     * of the function, and the module in which it lies. For example:
     * ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
     * If the symbol cannot be found but we know which module it is in,
     * return the module name and the offset from the beginning of the
     * module. If we don't even know the module, return the absolute
     * address as the offset.
     */
    public ResolveResult resolve(long addr, boolean demangle) {
        try (Arena arena = Arena.ofConfined()) {
            var sym = bcc_symbol.allocate(arena);
            int res;
            if (demangle) {
                res = Lib.bcc_symcache_resolve(cache, addr, sym);
            } else {
                res = Lib.bcc_symcache_resolve_no_demangle(cache, addr, sym);
            }
            if (res < 0) {
                if (bcc_symbol.module$get(sym) != null && bcc_symbol.offset$get(sym) != 0) {
                    return new ResolveResult(null, bcc_symbol.offset$get(sym), PanamaUtil.toString(bcc_symbol.module$get(sym)));
                }
                return new ResolveResult(null, addr, null);
            }
            String name_res;
            if (demangle) {
                name_res = PanamaUtil.toString(bcc_symbol.demangle_name$get(sym));
                Lib.bcc_symbol_free_demangle_name(sym);
            } else {
                name_res = PanamaUtil.toString(bcc_symbol.name$get(sym));
            }
            return new ResolveResult(name_res, bcc_symbol.offset$get(sym), PanamaUtil.toString(bcc_symbol.module$get(sym)));
        }
    }

    /**
     * Returns the kernel address or -1 on error for a given name in a given module
     */
    public long resolve_name(String module, String name) {
        Objects.requireNonNull(name);
        try (Arena arena = Arena.ofConfined()) {
            var addr = arena.allocate(8);
            var moduleStr = PanamaUtil.allocateNullOrString(arena, module);
            var nameStr = arena.allocateUtf8String(name);
            int res = Lib.bcc_symcache_resolve_name(cache, moduleStr, nameStr, addr);
            if (res < 0) {
                return -1;
            }
            return addr.get(ValueLayout.JAVA_LONG, 0);
        }
    }

}
