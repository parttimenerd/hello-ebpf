package me.bechberger.ebpf.bcc;

import me.bechberger.ebpf.bcc.raw.Lib;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.foreign.Arena;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Utils {

    public static void runCommand(String... command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String l;
            while ((l = reader.readLine()) != null) {
                System.out.println(l);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void triggerExecve(String path, String... args) {
        try (var arena = Arena.ofConfined()) {
            var pathNative = arena.allocateUtf8String(path);
            var argsNative = arena.allocateUtf8String(Stream.concat(Stream.of(path), Stream.of(args)).collect(Collectors.joining("\0")));
            var envNative = arena.allocateUtf8String("\0");
            var ret = Lib.execve(pathNative, argsNative, envNative);
        }
    }

    public static Thread triggerExecveInAsyncLoop(Supplier<Boolean> abort, String path, String... args) {
        var thread = new Thread(() -> {
            while (abort.get()) {
                triggerExecve(path, args);
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }
}
