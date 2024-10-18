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

    static class BPFNotSupported extends RuntimeException {
        public BPFNotSupported(String message, List<String> missingFeatures) {
            super(message + ": the following features are not available: " + String.join(", ", missingFeatures));
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
