package me.bechberger.ebpf.bcc;

import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Obtains all syscalls that are available on the current system
 */
public class Syscalls {

    public record Syscall(String name, int number) {
    }

    private static List<Syscall> syscalls = null;
    private static List<@Nullable Syscall> orderedSyscalls = null;

    private static Map<String, Syscall> syscallMap = null;

    private static void initIfNeeded() {
        if (syscalls == null) {
            try {
                syscalls = parse();
            } catch (IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }
            Map<Integer, Syscall> map = syscalls.stream().collect(Collectors.toMap(Syscall::number, s -> s));
            int max = syscalls.stream().mapToInt(Syscall::number).max().orElseThrow();
            orderedSyscalls = IntStream.range(0, max + 1).boxed().map(i -> map.getOrDefault(i, null)).toList();
            syscallMap = syscalls.stream().collect(Collectors.toMap(Syscall::name, s -> s));
        }
    }

    public static List<Syscall> getSyscalls() {
        initIfNeeded();
        return syscalls;
    }

    public static List<@Nullable Syscall> getOrderedSyscalls() {
        initIfNeeded();
        return orderedSyscalls;
    }

    public static Map<String, Syscall> getSyscallMap() {
        initIfNeeded();
        return syscallMap;
    }

    public static Syscall getSyscall(String name) {
        return getSyscallMap().get(name);
    }

    public static Syscall getSyscall(int number) {
        return getOrderedSyscalls().get(number);
    }

    private static List<Syscall> parse() throws IOException, InterruptedException {
        var process = Runtime.getRuntime().exec(new String[]{"cpp", "-dM"});
        process.getOutputStream().write("#include <sys/syscall.h>\n".getBytes());
        process.getOutputStream().close();
        int ret = process.waitFor();
        if (ret != 0) {
            throw new RuntimeException("Could not run cpp");
        }
        var output = new BufferedReader(new InputStreamReader(process.getInputStream()));
        var map = new HashMap<String, Integer>();
        return output.lines().filter(line -> line.matches("#define __NR[a-zA-Z0-9_]+ [0-9]+")).flatMap(line -> {
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
        }).toList();
    }

    public static void main(String[] args) {
        for (var syscall : getOrderedSyscalls()) {
            if (syscall != null) {
                System.out.println(syscall.name() + " " + syscall.number());
            }
        }
    }
}
