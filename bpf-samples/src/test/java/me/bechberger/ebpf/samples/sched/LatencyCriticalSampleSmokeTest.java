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
 * Kernel smoke test for the {@code preempt()} control-ring path (Sub-project B).
 *
 * <p>{@link LatencyCriticalSample} calls {@code preempt(pid)} for every task whose {@code comm}
 * matches {@code --critical}. That writes a {@code PREEMPT} record to the user→kernel control
 * ring; the BPF side drains it in {@code drainControlOne}, resolves the pid to its current CPU via
 * {@code bpf_task_from_pid}/{@code scx_bpf_task_cpu}, releases the task reference, and kicks that
 * CPU with {@code SCX_KICK_PREEMPT} — bumping the {@code PREEMPTS_ISSUED} stat.
 *
 * <p>A non-zero {@code PREEMPTS_ISSUED} therefore proves end-to-end: the control ring exists and
 * drains, the {@code bpf_task_from_pid}/{@code bpf_task_release} pair passes the verifier's
 * reference accounting, and the in-kernel {@code scx_bpf_kick_cpu} preempt actually ran. A clean
 * attach + detach (no verifier rejection, no reference leak) is the primary assertion.
 */
@ExtendWith(SchedulerExtension.class)
public class LatencyCriticalSampleSmokeTest {

    @Test
    @Timeout(90)
    void preemptsCriticalTasksInKernel() throws Exception {
        // Hogs run `yes` → their comm is "yes"; make that the critical comm so every hog that
        // reaches userspace enqueue triggers a preempt().
        var sched = new LatencyCriticalSample("yes");
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();
        // Pin hogs to a SINGLE CPU: on a many-CPU host (vng exposes 128 vCPUs) an unpinned hog
        // finds its own idle CPU via scx_bpf_select_cpu_dfl and dispatches locally, so nothing
        // reaches the userspace ring. Pinning everything to CPU 0 forces heavy contention so a
        // steady stream of tasks is routed to userspace and preempt() fires while dispatch()
        // is actively draining — the two must overlap for a control record to be consumed.
        spawnPinnedCpuHogs(12, "0", 9000);
        Thread.sleep(10_000);
        sched.requestExit();
        runner.join(30_000);

        // Reaching userspace enqueue at all proves the scheduler stayed attached.
        assertTrue(sched.preemptsRequested() > 0,
                "policy never matched a critical task, so preempt() was never called: "
                        + sched.formatStats());
        // The BPF side drained the control ring and issued an in-kernel SCX_KICK_PREEMPT.
        long issued = sched.preemptsIssued();
        assertTrue(issued > 0,
                "PREEMPTS_ISSUED is 0: control ring never drained or preempt path rejected"
                        + " (requested=" + sched.preemptsRequested()
                        + " submitOK=" + sched.controlSubmitted()
                        + " submitFail=" + sched.controlSubmitFailed()
                        + " unresolved=" + sched.preemptUnresolved()
                        + "): " + sched.formatStats());
    }

    /**
     * Start {@code n} CPU-burning {@code yes} children pinned (via {@code taskset -c <cpuList>}) to
     * a narrow CPU set so they contend and the scheduler must route surplus tasks to userspace.
     * Falls back to unpinned hogs if {@code taskset} is unavailable. Children are killed after
     * {@code durationMs}.
     */
    private static void spawnPinnedCpuHogs(int n, String cpuList, long durationMs) {
        List<Process> procs = new ArrayList<>(n);
        boolean taskset = hasTaskset();
        try {
            for (int i = 0; i < n; i++) {
                try {
                    ProcessBuilder pb = taskset
                            ? new ProcessBuilder("taskset", "-c", cpuList, "yes")
                            : new ProcessBuilder("yes");
                    pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
                    procs.add(pb.start());
                } catch (java.io.IOException e) {
                    throw new RuntimeException("spawnPinnedCpuHogs failed: " + e.getMessage(), e);
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
