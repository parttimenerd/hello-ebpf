package me.bechberger.ebpf.bpf.features.probes;

import me.bechberger.ebpf.bpf.raw.LibraryLoader;
import me.bechberger.ebpf.shared.PanamaUtil;
import me.bechberger.ebpf.shared.PanamaUtil.HandlerWithErrno;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * Lazy, cached vmlinux BTF handle. Loaded from
 * {@code /sys/kernel/btf/vmlinux} on first use; NULL/unavailable if the
 * file is not readable.
 */
public final class BtfLoader {

    static { LibraryLoader.load(); }

    private BtfLoader() {}

    private static final int BTF_KIND_STRUCT = 4;
    private static final int BTF_KIND_FUNC   = 12;

    private static final HandlerWithErrno<MemorySegment> BTF__PARSE =
            new HandlerWithErrno<>("btf__parse",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER));

    private static final HandlerWithErrno<Long> LIBBPF_GET_ERROR =
            new HandlerWithErrno<>("libbpf_get_error",
                    FunctionDescriptor.of(JAVA_LONG,
                            PanamaUtil.POINTER));

    private static final HandlerWithErrno<Integer> BTF__FIND_BY_NAME_KIND =
            new HandlerWithErrno<>("btf__find_by_name_kind",
                    FunctionDescriptor.of(JAVA_INT,
                            PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            JAVA_INT));

    private static final HandlerWithErrno<MemorySegment> BTF__TYPE_BY_ID =
            new HandlerWithErrno<>("btf__type_by_id",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            JAVA_INT));

    private static final HandlerWithErrno<MemorySegment> BTF__NAME_BY_OFFSET =
            new HandlerWithErrno<>("btf__name_by_offset",
                    FunctionDescriptor.of(PanamaUtil.POINTER,
                            PanamaUtil.POINTER,
                            JAVA_INT));

    private static volatile MemorySegment BTF = null;
    private static volatile Boolean AVAILABLE = null;
    private static final Object LOCK = new Object();

    private static void ensureLoaded() {
        if (AVAILABLE != null) return;
        synchronized (LOCK) {
            if (AVAILABLE != null) return;
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment path = arena.allocateFrom("/sys/kernel/btf/vmlinux");
                ProbeSyscallCounter.increment();
                PanamaUtil.ResultAndErr<MemorySegment> pr =
                        BTF__PARSE.call(arena, path, MemorySegment.NULL);
                MemorySegment btf = pr.result();
                if (btf == null || btf.address() == 0) {
                    BTF = null;
                    AVAILABLE = false;
                    return;
                }
                PanamaUtil.ResultAndErr<Long> er = LIBBPF_GET_ERROR.call(arena, btf);
                if (er.result() != 0L) {
                    BTF = null;
                    AVAILABLE = false;
                    return;
                }
                BTF = btf;
                AVAILABLE = true;
            } catch (Throwable t) {
                BTF = null;
                AVAILABLE = false;
            }
        }
    }

    public static boolean isAvailable() {
        ensureLoaded();
        return Boolean.TRUE.equals(AVAILABLE);
    }

    public static boolean hasFuncByName(String name) {
        return findByName(name, BTF_KIND_FUNC);
    }

    public static boolean hasStructByName(String name) {
        return findByName(name, BTF_KIND_STRUCT);
    }

    private static boolean findByName(String name, int kind) {
        if (!isAvailable()) return false;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment n = arena.allocateFrom(name);
            PanamaUtil.ResultAndErr<Integer> r =
                    BTF__FIND_BY_NAME_KIND.call(arena, BTF, n, kind);
            int id = r.result();
            if (id <= 0) return false;
            // Some libbpf builds on certain kernels return a stale positive id
            // for a name that is not actually present. Verify by reading the
            // matched type's name back and confirming it equals the query.
            return nameOfType(arena, id).equals(name);
        } catch (Throwable t) {
            return false;
        }
    }

    /** Resolve the name of the BTF type with the given id, or "" if unavailable. */
    private static String nameOfType(Arena arena, int id) {
        PanamaUtil.ResultAndErr<MemorySegment> tr = BTF__TYPE_BY_ID.call(arena, BTF, id);
        MemorySegment type = tr.result();
        if (type == null || type.address() == 0) return "";
        // struct btf_type begins with __u32 name_off at offset 0.
        int nameOff = type.reinterpret(Integer.BYTES).get(JAVA_INT, 0);
        PanamaUtil.ResultAndErr<MemorySegment> nr = BTF__NAME_BY_OFFSET.call(arena, BTF, nameOff);
        MemorySegment namePtr = nr.result();
        if (namePtr == null || namePtr.address() == 0) return "";
        return namePtr.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /**
     * Drops the cached vmlinux BTF handle so the next probe re-parses
     * {@code /sys/kernel/btf/vmlinux} from scratch. Test-only: guards against
     * a stale handle leaking across test classes when the full reactor runs
     * many BPF-loading tests in one JVM.
     */
    public static void resetForTest() {
        synchronized (LOCK) {
            BTF = null;
            AVAILABLE = null;
        }
    }
}
