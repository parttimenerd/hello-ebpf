package me.bechberger.ebpf.bpf;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class TestUtil {
    /**
     * Triggers a openat syscall and returns the path of the file that was opened
     */
    public static Path triggerOpenAt() {
        try {
            var path = Files.createTempFile("test", "txt");
            Files.write(path, "Hello, World!".getBytes());
            Files.delete(path);
            return path;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Start {@code n} CPU-burning child processes and kill them after {@code durationMs}.
     * Each process runs {@code yes > /dev/null} which is a simple CPU hog.
     * This helper is used by integration tests to generate work for the scheduler.
     *
     * @param n          number of processes to start
     * @param durationMs how long to let them run before killing
     */
    public static void spawnCpuHogs(int n, long durationMs) {
        List<Process> procs = new ArrayList<>(n);
        try {
            for (int i = 0; i < n; i++) {
                try {
                    procs.add(new ProcessBuilder("sh", "-c", "yes > /dev/null").start());
                } catch (java.io.IOException e) {
                    throw new RuntimeException("spawnCpuHogs failed: " + e.getMessage(), e);
                }
            }
            Thread.sleep(durationMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            for (Process p : procs) {
                p.destroyForcibly();
            }
        }
    }
}
