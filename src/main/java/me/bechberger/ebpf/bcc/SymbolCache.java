package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.raw.Lib;
import me.bechberger.ebpf.raw.bcc_symbol;
import org.jetbrains.annotations.Nullable;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.lang.foreign.ValueLayout;

/**

 Caches the kernel symbols

 {@snippet :
 class SymbolCache(object):
    def __init__(self, pid):
        self.cache = lib.bcc_symcache_new(
                pid, ct.cast(None, ct.POINTER(bcc_symbol_option)))

    def resolve(self, addr, demangle):
        """
        Return a tuple of the symbol (function), its offset from the beginning
        of the function, and the module in which it lies. For example:
            ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
        If the symbol cannot be found but we know which module it is in,
        return the module name and the offset from the beginning of the
        module. If we don't even know the module, return the absolute
        address as the offset.
        """

        sym = bcc_symbol()
        if demangle:
            res = lib.bcc_symcache_resolve(self.cache, addr, ct.byref(sym))
        else:
            res = lib.bcc_symcache_resolve_no_demangle(self.cache, addr,
                                                       ct.byref(sym))
        if res < 0:
            if sym.module and sym.offset:
                return (None, sym.offset,
                        ct.cast(sym.module, ct.c_char_p).value)
            return (None, addr, None)
        if demangle:
            name_res = sym.demangle_name
            lib.bcc_symbol_free_demangle_name(ct.byref(sym))
        else:
            name_res = sym.name
        return (name_res, sym.offset, ct.cast(sym.module, ct.c_char_p).value)

    def resolve_name(self, module, name):
        module = _assert_is_bytes(module)
        name = _assert_is_bytes(name)
        addr = ct.c_ulonglong()
        if lib.bcc_symcache_resolve_name(self.cache, module, name,
                ct.byref(addr)) < 0:
            return -1
        return addr.value
  }
 */
// complete
public class SymbolCache {

        public static record ResolveResult(String symbol, long offset, String module) {
        }

        private final MemorySegment cache;

        public SymbolCache(int pid) {
            this.cache = Lib.bcc_symcache_new(pid, null);
        }

    /**
     *         Return a tuple of the symbol (function), its offset from the beginning
     *         of the function, and the module in which it lies. For example:
     *             ("start_thread", 0x202, "/usr/lib/.../libpthread-2.24.so")
     *         If the symbol cannot be found but we know which module it is in,
     *         return the module name and the offset from the beginning of the
     *         module. If we don't even know the module, return the absolute
     *         address as the offset.
     */
        public ResolveResult resolve(long addr, boolean demangle) {
            try (Arena arena = Arena.ofAuto()) {
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

        /** returns the kernel address or -1 on error */
        public long resolve_name(String module, String name) {
            try (Arena arena = Arena.ofAuto()) {
                var addr = arena.allocate(8);
                var moduleStr = arena.allocateUtf8String(module);
                var nameStr = arena.allocateUtf8String(name);
                int res = Lib.bcc_symcache_resolve_name(cache, moduleStr, nameStr, addr);
                if (res < 0) {
                    return -1;
                }
                return addr.get(ValueLayout.JAVA_LONG, 8);
            }
        }

}
