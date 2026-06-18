package me.bechberger.ebpf.shared;

import me.bechberger.ebpf.annotations.bpf.Requires;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Utility class to check for required kernel features, specified via the {@link Requires} annotation
 */
public class KernelFeatures {

    /**
     * Minimum kernel version supported by hello-ebpf.
     * <p>
     * 6.17 is the floor because BPF arenas
     * ({@code BPF_MAP_TYPE_ARENA}, {@code bpf_arena_alloc_pages}) and
     * Clang 17+ {@code __BPF_FEATURE_ADDR_SPACE_CAST} (which makes
     * {@code cast_kern}/{@code cast_user} a no-op) need this. Older kernels
     * may load simpler programs but the project tests and ergonomics
     * assume 6.17.
     */
    public static final int MIN_KERNEL_MAJOR = 6;
    public static final int MIN_KERNEL_MINOR = 17;

    /** Kernel-version pair parsed from {@code /proc/sys/kernel/osrelease}. */
    public record KernelVersion(int major, int minor) {
        public boolean isAtLeast(int reqMajor, int reqMinor) {
            return major > reqMajor || (major == reqMajor && minor >= reqMinor);
        }
        @Override public String toString() { return major + "." + minor; }
    }

    static class BPFNotSupported extends RuntimeException {
        public BPFNotSupported(String message, List<String> missingFeatures) {
            super(message + ": the following features are not available: " + String.join(", ", missingFeatures));
        }
    }

    /**
     * Read and parse the running kernel version from
     * {@code /proc/sys/kernel/osrelease}. Returns {@code null} when the file
     * is missing (e.g. running on macOS during build).
     */
    public static KernelVersion currentKernelVersion() {
        Path p = Path.of("/proc/sys/kernel/osrelease");
        if (!Files.exists(p)) {
            return null;
        }
        try {
            String s = Files.readString(p).trim();
            // Strip anything after the first non-digit-or-dot (e.g. "6.17.0-35-generic")
            int dot1 = s.indexOf('.');
            if (dot1 < 0) return null;
            int dot2 = s.indexOf('.', dot1 + 1);
            int dash = s.indexOf('-');
            int end = s.length();
            if (dot2 >= 0) end = Math.min(end, dot2);
            if (dash >= 0) end = Math.min(end, dash);
            int major = Integer.parseInt(s.substring(0, dot1));
            int minor = Integer.parseInt(s.substring(dot1 + 1, end));
            return new KernelVersion(major, minor);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Throws if the running kernel is older than {@link #MIN_KERNEL_MAJOR}.{@link #MIN_KERNEL_MINOR}.
     * Skips the check when {@code /proc/sys/kernel/osrelease} is unreadable
     * (the file is a Linux-only interface).
     */
    public static void requireMinimumKernel() {
        KernelVersion v = currentKernelVersion();
        if (v == null) return;
        if (!v.isAtLeast(MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR)) {
            throw new RuntimeException(
                    "hello-ebpf requires Linux kernel >= "
                            + MIN_KERNEL_MAJOR + "." + MIN_KERNEL_MINOR
                            + ", found " + v
                            + ". Older kernels lack BPF arenas and the address-space"
                            + " cast feature this project depends on.");
        }
    }

    public static List<String> getMissingFeatures(Set<String> requiredFeatures) {
        List<String> availableFeatures = getAvailableKernelFeatures();
        List<String> missingFeatures = new ArrayList<>();
        for (var feature : requiredFeatures) {
            if (!availableFeatures.contains(feature)) {
                missingFeatures.add(feature);
            }
        }
        Collections.sort(missingFeatures);
        return missingFeatures;
    }

    public static void checkRequirements(String message, Class<?> clazz) {
        var missingFeatures = getMissingFeatures(getRequiredKernelFeatures(clazz));
        if (!missingFeatures.isEmpty()) {
            throw new BPFNotSupported(message, missingFeatures);
        }
    }

    private static Set<String> getRequiredKernelFeatures(Class<?> clazz) {
        // get all requirements recursively
        Set<String> requirements = new HashSet<>();
        Requires requires = clazz.getAnnotation(Requires.class);
        if (requires != null) {
            requirements.addAll(getRequiredKernelFeatures(requires));
        }
        for (var iface : clazz.getInterfaces()) {
            requirements.addAll(getRequiredKernelFeatures(iface));
        }
        return requirements;
    }

    public static List<String> getRequiredKernelFeatures(Requires requires) {
        return Arrays.stream(requires.getClass().getMethods())
                .filter(method -> {
                    try {
                        return (boolean) method.invoke(requires);
                    } catch (Exception e) {
                        return false;
                    }
                })
                .map(Method::getName)
                .toList();
    }

    public static List<String> getAvailableKernelFeatures() {
        List<String> availableFeatures = new ArrayList<>();
        if (Files.exists(Path.of("/sys/kernel/sched_ext/"))) {
            availableFeatures.add("sched_ext");
        }
        return availableFeatures;
    }

    private static boolean checkThatNativeFunctionExists(String functionName) {
        try {
            PanamaUtil.lookup(functionName);
            return true;
        } catch (NoSuchElementException e) {
            return false;
        }
    }
}
