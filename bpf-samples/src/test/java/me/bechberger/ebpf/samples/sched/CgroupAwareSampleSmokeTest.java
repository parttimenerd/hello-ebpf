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
 * Kernel smoke test for the {@code @TaskExtension} end-to-end path.
 *
 * <p>{@link CgroupAwareSample} loads {@link CgroupAwareSchedBpf}, a cross-module {@code @BPF}
 * subclass of the jar-only {@code UserspaceSchedulerBase}. That base has an arena-using
 * {@code struct_ops} entry ({@code update_idle -> setBit} dereferencing the {@code idleMask}
 * arena). For the subclass to LOAD, the inherited entry must re-inject the per-arena
 * association call {@code bpf_arena_associate_idleMask();}; otherwise the verifier rejects it
 * with "addr_space_cast ... has an associated arena". A successful attach therefore proves the
 * cross-module arena-association shim works.
 *
 * <p>The base also creates a second dispatch queue ({@code FRAMEWORK_DSQ}) via a
 * {@code @BPFAbstraction} field initializer whose {@code scx_bpf_create_dsq(FRAMEWORK_DSQ, -1)}
 * prologue is lifted into {@code init()}. Because the subclass inherits {@code init()} as a
 * raw-C body, that prologue must be re-injected at subclass compile time — otherwise the
 * scheduler attaches but aborts at the first {@code dispatch} with a kernel "invalid DSQ ID"
 * runtime error. A clean run therefore also proves the cross-module abstraction-prologue shim.
 *
 * <p>A non-zero cgroup id observed on the policy side additionally proves that
 * {@code fillExtension} stamped the per-task extension tail in the kernel and Java read it back
 * type-safely via {@code QueuedTask.ext(CgroupExt.class)}.
 */
@ExtendWith(SchedulerExtension.class)
public class CgroupAwareSampleSmokeTest {

    @Test
    @Timeout(90)
    void attachesAndReadsNonZeroCgroupId() throws Exception {
        var sched = new CgroupAwareSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();
        // Generate scheduling activity so tasks flow through enqueue -> fillExtension -> policy.
        // The hogs are PINNED to a narrow CPU set: on a many-CPU host (e.g. vng exposes 128
        // vCPUs) an unpinned hog always finds its own idle CPU via scx_bpf_select_cpu_dfl and is
        // dispatched locally, so nothing ever reaches the userspace ring and the policy observes
        // zero tasks. Pinning forces contention, so surplus tasks are routed to userspace.
        spawnPinnedCpuHogs(6, "0-1", 5000);
        Thread.sleep(6000);
        sched.requestExit();
        runner.join(30_000);

        // Attach + workload succeeded (no arena rejection, no invalid-DSQ abort) if we observed
        // any task: reaching enqueue -> ring -> Java drain proves the scheduler stayed attached.
        assertTrue(sched.observedTasks() > 0,
                "no tasks observed on the policy side: " + sched.formatStats());
        // fillExtension wrote a real cgroup id and Java read it back.
        assertTrue(sched.nonZeroCgroup() > 0,
                "no non-zero cgroup id observed; @TaskExtension tail did not flow through: "
                        + sched.formatStats());
        assertNotEquals(0L, sched.lastCgroupId(),
                "lastCgroupId must be non-zero: " + sched.formatStats());
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
                try {
                    ProcessBuilder pb = taskset
                            ? new ProcessBuilder("taskset", "-c", cpuList, "sh", "-c", "yes > /dev/null")
                            : new ProcessBuilder("sh", "-c", "yes > /dev/null");
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
