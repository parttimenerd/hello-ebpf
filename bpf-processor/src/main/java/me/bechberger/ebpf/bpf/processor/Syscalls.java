package me.bechberger.ebpf.bpf.processor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

/**
 * Helps to create code for syscalls
 */
public class Syscalls {

    public record Syscall(String name, String definition, String description) {
        public boolean isUnknown() {
            return definition.equals("unknown");
        }
    }

    public static List<Syscall> parse() throws IOException, InterruptedException {
        Map<String, Syscall> syscalls = new HashMap<>();
        Files.list(Constants.TRACEFS.resolve("events/syscalls")).forEach(folder -> {
            String name = folder.getFileName().toString();
            if (name.startsWith("sys_enter_")) {
                String syscall = name.substring("sys_enter_".length());
                if (!syscalls.containsKey(syscall)) {
                    syscalls.putAll(processSyscall(syscall));
                }
            }
        });
        return syscalls.entrySet().stream().sorted(Comparator.comparing(Entry::getKey)).map(Entry::getValue).collect(Collectors.toList());
    }

    /**
     * Use the man command to get the syscall definition and description
     * @param name name of the syscall
     * @return obtained information for the syscall and others from the same man page
     */
    public static Map<String, Syscalls.Syscall> processSyscall(String name) {
        // call man 2 name
        Map<String, Syscall> ret = new HashMap<>();
        try {
            Process process = new ProcessBuilder(List.of("man", "2", name)).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            var lines = reader.lines().toList();
            if (process.waitFor() != 0 || lines.size() < 10) {
                ret.put(name, new Syscall(name, "unknown", "unknown"));
                return ret;
            }
            // find line that starts with SYNOPSIS
            var synopsis = findSynopsisSection(lines);

            var wholeString = String.join("\n", lines);

            for (var foundName : getSyscallsFromManPage(lines)) {
                try {
                    var definition = synopsis.stream().filter(l -> l.contains(" " + name + "(") || l.contains("*" + name + "(")).findFirst().orElseGet(() -> {
                        var known = " syscall(SYS_" + foundName;
                        var line = synopsis.stream().filter(l -> l.contains(known)).findFirst().orElseThrow();
                        var returnType = line.substring(0, line.indexOf(known));
                        var args = Arrays.stream(line.substring(line.indexOf(known) + known.length()).split("\\)")[0].split(",")).map(String::strip).collect(Collectors.joining(", "));
                        // something like int syscall(SYS_ioprio_get, int which, int who);
                        // find definition and create C definition yourself
                        return returnType + " " + foundName + "(" + args + ");";
                    });
                    ret.put(foundName, new Syscall(foundName, definition, wholeString));
                } catch (NoSuchElementException e) {}
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return ret;
    }

    private static List<String> findSynopsisSection(List<String> lines) {
        int synIndex = lines.indexOf("SYNOPSIS");
        int descIndex = lines.indexOf("DESCRIPTION");
        return lines.subList(synIndex + 1, descIndex);
    }

    private static List<String> getSyscallsFromManPage(List<String> lines) {
        var namesLine = lines.get(lines.indexOf("NAME") + 1);
        return Arrays.stream(namesLine.trim().split("-")[0].split(",")).map(String::trim).toList();
    }
}