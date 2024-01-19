package me.bechberger.ebpf.bcc;

import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Obtains all syscalls that are available on the current system
 */
public class Syscalls {

    private static final List<Path> possibleLocations = List.of(
            Path.of("/usr/include/asm-generic/unistd.h"),
            Path.of("/usr/include/asm/asm/unistd_64.h")
    );

    public record Syscall(String name, int number) {
    }

    private static List<Syscall> syscalls = null;
    private static List<@Nullable Syscall> orderedSyscalls = null;

    public static List<Syscall> getSyscalls() {
        if (syscalls == null) {
            syscalls = parse(possibleLocations);
            Map<Integer, Syscall> map = syscalls.stream().collect(Collectors.toMap(Syscall::number, s -> s));
            int max = syscalls.stream().mapToInt(Syscall::number).max().orElseThrow();
            orderedSyscalls = IntStream.range(0, max + 1).boxed().map(i -> map.getOrDefault(i, null)).toList();
        }
        return syscalls;
    }

    public static List<@Nullable Syscall> getOrderedSyscalls() {
        if (orderedSyscalls == null) {
            getSyscalls();
        }
        return orderedSyscalls;
    }

    private static List<Syscall> parse(List<Path> possibleLocations) {
        for (var location : possibleLocations) {
            if (location.toFile().exists()) {
                try {
                    return parse(location);
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        throw new RuntimeException("Could not find syscalls");
    }

    private static List<Syscall> parse(Path location) throws IOException, InterruptedException {
        // read output of clang -dM -E location || gcc -dM -E location
        // and parse lines of format #define __NR_<syscall nam> <number>
        // into Syscall objects
        var process = Runtime.getRuntime().exec("clang -dM -E " + location);
        process.waitFor();
        var output = new BufferedReader(new InputStreamReader(process.getInputStream()));
        var map = new HashMap<String, Integer>();
        return output.lines()
                .filter(line -> line.matches("#define __NR[a-zA-Z0-9_]+ [0-9]+"))
                .flatMap(line -> {
                    var parts = line.split(" ");
                    if (parts[1].startsWith("__NR_")) {
                        var name = parts[1].substring("__NR_".length());
                        if (map.containsKey(parts[2])) {
                            return Stream.of(new Syscall(name, map.get(parts[2])));
                        }
                        var number = Integer.parseInt(parts[2]);
                        return Stream.of(new Syscall(name, number));
                    }
                    map.put(parts[1], Integer.parseInt(parts[2]));
                    return Stream.empty();
                })
                .toList();
    }

    public static void main(String[] args) {
        for (var syscall : getOrderedSyscalls()) {
            if (syscall != null) {
                System.out.println(syscall.name() + " " + syscall.number());
            }
        }
    }
}
