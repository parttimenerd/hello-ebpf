// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.userspace.Opts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Kernel smoke test for the BPF&rarr;Java signal path (Sub-project B, Task 11).
 *
 * <p>{@link LockBoostSchedBpf#runnable} emits a {@code LOCK_ACQUIRED} signal for every
 * task whose {@code comm} is {@link LockBoostSchedBpf#WATCHED_COMM} ({@code "lockholder"}).
 * The framework delivers each signal to {@link LockBoostSignalSample#onSignal}, which
 * calls {@code preempt(pid)} — writing a PREEMPT control record that the BPF side turns
 * into an in-kernel {@code SCX_KICK_PREEMPT}.
 *
 * <p>The test spawns CPU-burning children whose {@code comm} is {@code "lockholder"}
 * (via {@code exec -a}), pinned to a single CPU so they keep becoming runnable under
 * contention. It then asserts the full chain fired:
 * <ul>
 *   <li>{@code signalsDelivered() > 0} — a BPF {@code emitSignal} ran (the overridden
 *       {@code runnable} callback re-emitted from the subclass and called the inherited
 *       {@code @BPFFunction}, proving the codegen path);</li>
 *   <li>{@code signalsSeen() > 0} — Java drained the signals ring and dispatched to
 *       {@code onSignal};</li>
 *   <li>{@code preemptsIssued() > 0} — {@code onSignal}'s {@code preempt} reached the
 *       control ring and issued an in-kernel kick.</li>
 * </ul>
 * A clean attach + detach (no verifier rejection of the subclass program) is the
 * primary assertion.
 */
@ExtendWith(SchedulerExtension.class)
public class LockBoostSignalSampleSmokeTest {

    @Test
    @Timeout(90)
    void boostsWatchedTasksViaSignalPath() throws Exception {
        var sched = new LockBoostSignalSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();
        // comm == "lockholder" so LockBoostSchedBpf.runnable emits LOCK_ACQUIRED for them.
        // The hogs sleep-spin (wake ~1000×/s) so each wakeup is a fresh runnable()
        // callback → a signal emit; pinned to CPU 0 so they also contend.
        spawnNamedCpuHogs(8, "lockholder", "0", 9000);
        Thread.sleep(10_000);
        sched.requestExit();
        runner.join(30_000);

        // A BPF emitSignal actually ran: the subclass-overridden runnable callback
        // re-emitted correctly and called the inherited emitSignal @BPFFunction.
        long delivered = sched.signalsDelivered();
        assertTrue(delivered > 0,
                "SIGNALS_DELIVERED is 0: the BPF runnable override never emitted"
                        + " (dropped=" + sched.signalsDropped() + "): " + sched.formatStats());
        // Java drained the signals ring and dispatched to onSignal.
        assertTrue(sched.signalsSeen() > 0,
                "onSignal never fired despite SIGNALS_DELIVERED>0: " + sched.formatStats());
        // onSignal's preempt() reached the control ring and issued an in-kernel kick.
        assertTrue(sched.preemptsIssued() > 0,
                "PREEMPTS_ISSUED is 0: onSignal->preempt->control-ring->kick broke"
                        + " (boostsIssued=" + sched.boostsIssued()
                        + " unresolved=" + sched.preemptUnresolved()
                        + "): " + sched.formatStats());
    }

    /**
     * Start {@code n} CPU-burning children whose {@code comm} is {@code name}, pinned via
     * {@code taskset -c <cpuList>} to force contention. Each child is a copy of a tiny
     * sleep-spin script whose filename is {@code name} — the kernel sets {@code comm} to
     * the script's basename (truncated to 15 chars), which is how the BPF {@code runnable}
     * callback recognises them. The sleep-spin loop wakes ~1000×/s so each wakeup is a
     * fresh {@code runnable} transition (a signal-emit opportunity). Children and the temp
     * dir are cleaned up after {@code durationMs}.
     */
    private static void spawnNamedCpuHogs(int n, String name, String cpuList, long durationMs) {
        List<Process> procs = new ArrayList<>(n);
        boolean taskset = hasTaskset();
        java.nio.file.Path dir = null;
        try {
            // A script file literally named <name>: executing it makes the child's comm
            // == <name>. `exec -a` / renaming `yes` don't work here (coreutils multiplexer
            // rejects argv0 mismatch, and comm derives from the executable basename anyway).
            dir = java.nio.file.Files.createTempDirectory("lockboost-hog");
            java.nio.file.Path script = dir.resolve(name);
            java.nio.file.Files.writeString(script,
                    "#!/bin/bash\nwhile :; do sleep 0.001; done\n");
            script.toFile().setExecutable(true);
            String path = script.toString();
            for (int i = 0; i < n; i++) {
                try {
                    ProcessBuilder pb = taskset
                            ? new ProcessBuilder("taskset", "-c", cpuList, path)
                            : new ProcessBuilder(path);
                    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                    pb.redirectError(ProcessBuilder.Redirect.DISCARD);
                    procs.add(pb.start());
                } catch (java.io.IOException e) {
                    throw new RuntimeException("spawnNamedCpuHogs failed: " + e.getMessage(), e);
                }
            }
            Thread.sleep(durationMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (java.io.IOException e) {
            throw new RuntimeException("spawnNamedCpuHogs setup failed: " + e.getMessage(), e);
        } finally {
            for (Process p : procs) {
                p.destroyForcibly();
            }
            if (dir != null) {
                try (var paths = java.nio.file.Files.walk(dir)) {
                    paths.sorted(java.util.Comparator.reverseOrder())
                            .forEach(p -> { try { java.nio.file.Files.deleteIfExists(p); }
                                            catch (java.io.IOException ignored) {} });
                } catch (java.io.IOException ignored) {}
            }
        }
    }

    private static boolean hasTaskset() {
        try {
            return new ProcessBuilder("taskset", "--version")
                    .redirectErrorStream(true)
                    .start()
                    .waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
