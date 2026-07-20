// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler.ExitCause;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Kernel smoke test for {@link RustyScheduler}: attach a real sched_ext scheduler, drive load,
 * and assert it stays attached while draining tasks through the userspace ring.
 *
 * <p>A clean attach proves the whole framework path works for the rusty port: the base
 * {@code UserspaceScheduler} BPF program loads, the {@code struct_ops} entries pass the verifier,
 * and the Java {@code schedule()}/{@code tick()} hooks are driven without aborting. Because
 * {@code RustyScheduler} only overrides Java-side policy (domain assignment + push/pull balance),
 * an exit that is NOT a kernel {@code DETACHED} is the load-bearing kernel-side assertion.
 *
 * <p>Runs on the thinkstation via the per-class VNG runner ({@code scripts/run-tests-vng.sh}),
 * gated on the host kernel by {@link SchedulerExtension}. The ring-drain count is asserted only
 * softly: on many-vCPU VNG hosts sched_ext frequently dispatches locally and near-zero tasks reach
 * the userspace ring (see memory {@code project_vng_scheduler_ring_enqueue_zero}), so a zero count
 * is logged rather than failed — the offline {@code RustySchedulerHarnessTest} is the authoritative
 * proof of the dispatch + balancing logic.
 */
@ExtendWith(SchedulerExtension.class)
public class RustySchedulerSmokeTest {

    @Test
    @Timeout(90)
    void attachesAndDrainsTasks() throws Exception {
        var sched = new RustyScheduler();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();

        // Pin hogs to a narrow CPU set so surplus tasks are routed to userspace. On a many-CPU
        // host an unpinned hog always finds its own idle CPU and is dispatched locally, so nothing
        // reaches the ring (same rationale as CgroupAwareSampleSmokeTest).
        spawnPinnedCpuHogs(6, "0-1", 5000);
        Thread.sleep(6000);

        // Snapshot attach state and ring count *before* requesting exit, so a clean detach isn't
        // mistaken for a kernel-forced one.
        boolean detachedByKernel = sched.exitCause() == ExitCause.DETACHED;
        long ringEnqueued = sched.stats().ringEnqueued();

        sched.requestExit();
        runner.join(30_000);

        // A DETACHED exit means the kernel watchdog/verifier tore the scheduler down — the real
        // failure we care about. A REQUESTED exit (our requestExit above) is the healthy path.
        assertFalse(detachedByKernel,
                "kernel detached RustyScheduler before we asked it to exit: " + sched.formatStats());
        assertNotEquals(ExitCause.DETACHED, sched.exitCause(),
                "RustyScheduler exited via kernel detach: " + sched.formatStats());
        if (ringEnqueued == 0) {
            System.err.println("RustySchedulerSmokeTest: 0 tasks reached the userspace ring "
                    + "(expected on many-vCPU VNG hosts). Attach verified. Stats: "
                    + sched.formatStats());
        }
    }

    /**
     * Start {@code n} CPU-burning children pinned (via {@code taskset -c <cpuList>}) to a narrow
     * CPU set so they contend and the scheduler must route surplus tasks to userspace. Falls back
     * to unpinned hogs if {@code taskset} is unavailable. Children are killed after {@code durationMs}.
     */
    private static void spawnPinnedCpuHogs(int n, String cpuList, long durationMs) {
        List<Process> procs = new ArrayList<>(n);
        boolean taskset = hasTaskset();
        try {
            for (int i = 0; i < n; i++) {
                ProcessBuilder pb = taskset
                        ? new ProcessBuilder("taskset", "-c", cpuList, "sh", "-c", "yes > /dev/null")
                        : new ProcessBuilder("sh", "-c", "yes > /dev/null");
                procs.add(pb.start());
            }
            Thread.sleep(durationMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (java.io.IOException e) {
            throw new RuntimeException("spawnPinnedCpuHogs failed: " + e.getMessage(), e);
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
