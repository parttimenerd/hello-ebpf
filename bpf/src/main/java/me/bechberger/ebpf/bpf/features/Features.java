package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runtime BPF capability probing. Every {@code hasX(...)} answers
 * "does this kernel support X?" via a cached probe.
 *
 * <p>Results are cached for the lifetime of the JVM. First call fires the
 * probe (one or two syscalls); every subsequent call hits the in-memory
 * cache. Cache reset is test-only.
 */
public final class Features {

    private Features() {}

    /** Dispatcher indirection so tests can substitute a stub. */
    interface Dispatcher {
        ProbeResult probe(ProbeKey key);
    }

    private static volatile Dispatcher dispatcher = null;
    private static final ConcurrentHashMap<ProbeKey, ProbeResult> CACHE =
            new ConcurrentHashMap<>();

    public static boolean hasProgramType(BPFProgramType t) {
        return probeProgramType(t).isSupported();
    }
    public static boolean hasMapType(MapTypeId t) {
        return probeMapType(t).isSupported();
    }
    public static boolean hasHelper(BPFHelper h) {
        return probeHelper(h).isSupported();
    }
    public static boolean hasKfunc(String name) {
        return probeKfunc(name, null).isSupported();
    }
    public static boolean hasKfunc(String name, String moduleName) {
        return probeKfunc(name, moduleName).isSupported();
    }
    public static boolean hasStructOps(String kernelStructName) {
        return probeStructOps(kernelStructName).isSupported();
    }
    public static boolean hasAttachType(BPFAttachType t) {
        return probeAttachType(t).isSupported();
    }

    public static ProbeResult probeProgramType(BPFProgramType t) {
        return cached(new ProbeKey.ProgramTypeKey(t));
    }
    public static ProbeResult probeMapType(MapTypeId t) {
        return cached(new ProbeKey.MapTypeKey(t));
    }
    public static ProbeResult probeHelper(BPFHelper h) {
        return cached(new ProbeKey.HelperKey(h));
    }
    public static ProbeResult probeKfunc(String name, @Nullable String moduleName) {
        return cached(new ProbeKey.KfuncKey(name, moduleName));
    }
    public static ProbeResult probeStructOps(String kernelStructName) {
        return cached(new ProbeKey.StructOpsKey(kernelStructName));
    }
    public static ProbeResult probeAttachType(BPFAttachType t) {
        return cached(new ProbeKey.AttachTypeKey(t));
    }

    private static volatile KernelVersion CACHED_VERSION = null;
    public static KernelVersion kernelVersion() {
        var v = CACHED_VERSION;
        if (v != null) return v;
        try {
            String release = java.nio.file.Files.readString(
                    java.nio.file.Path.of("/proc/sys/kernel/osrelease")).trim();
            v = KernelVersion.parse(release);
        } catch (Exception e) {
            v = new KernelVersion(0, 0, 0, "unknown");
        }
        CACHED_VERSION = v;
        return v;
    }

    /**
     * Probe every commonly-checked feature and return a name-keyed snapshot.
     * Fires every probe on cold cache; on warm cache returns the cached values.
     */
    public static Map<String, ProbeResult> snapshot() {
        Map<String, ProbeResult> out = new LinkedHashMap<>();
        for (var t : BPFProgramType.values()) {
            out.put("prog:" + t.name(), probeProgramType(t));
        }
        for (var t : MapTypeId.values()) {
            out.put("map:" + t.name(), probeMapType(t));
        }
        for (var h : BPFHelper.values()) {
            out.put("helper:" + h.name(), probeHelper(h));
        }
        for (var a : BPFAttachType.values()) {
            out.put("attach:" + a.name(), probeAttachType(a));
        }
        return Collections.unmodifiableMap(out);
    }

    /** Clear the cache. Test-only. */
    static void resetCacheForTest() {
        CACHE.clear();
        CACHED_VERSION = null;
    }

    /** Substitute the dispatcher. Test-only. */
    static void setDispatcherForTest(Dispatcher d) {
        dispatcher = d;
    }

    private static ProbeResult cached(ProbeKey key) {
        return CACHE.computeIfAbsent(key, k -> {
            Dispatcher d = dispatcher;
            if (d == null) {
                return new ProbeResult.ProbeUnavailable(
                        "no probe dispatcher wired (running on non-Linux?)");
            }
            return d.probe(k);
        });
    }
}
