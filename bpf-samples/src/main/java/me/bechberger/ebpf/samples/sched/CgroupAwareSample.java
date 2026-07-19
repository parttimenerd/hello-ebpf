// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.TaskExtension;
import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.UserspaceSchedulerBase;
import me.bechberger.ebpf.bpf.userspace.Opts;
import me.bechberger.ebpf.bpf.userspace.UserspaceScheduler;

/**
 * <b>Experimental</b> — end-to-end demonstration of the {@code @TaskExtension} path.
 *
 * <p>This is the policy (Java) side. It pairs with {@link CgroupAwareSchedBpf}, the
 * {@code @BPF} transport subclass that stamps a task's cgroup id and parent tgid into
 * the per-task extension tail during {@code enqueue}. This sample reads those bytes
 * back type-safely through {@link QueuedTask#ext(Class)} and observes them.
 *
 * <p>Scheduling itself is trivial FIFO ({@code policy} returns {@link #ANY_CPU}); the
 * point of the demo is to prove the custom BPF-computed values flow all the way from
 * the kernel enqueue path into Java.
 */
public final class CgroupAwareSample extends UserspaceScheduler {

    /**
     * Read-side view of the extension tail. Component order and types MUST match the
     * writes in {@link CgroupAwareSchedBpf#fillExtension}: {@code cgroupId} at tail
     * offset 0, {@code ppid} at offset 8 (both native little-endian 8-byte longs).
     */
    @TaskExtension
    public record CgroupExt(long cgroupId, long ppid) {}

    private volatile long observedTasks;
    private volatile long nonZeroCgroup;
    private volatile long lastCgroupId;
    private volatile long lastPpid;

    // Throttle logging: policy runs on the hot path.
    private long logThrottle;

    @Override
    protected Class<? extends UserspaceSchedulerBase> bpfProgramClass() {
        return CgroupAwareSchedBpf.class;
    }

    @Override
    protected int policy(QueuedTask t) {
        CgroupExt ext = t.ext(CgroupExt.class);
        observedTasks++;
        if (ext.cgroupId() != 0L) {
            nonZeroCgroup++;
            lastCgroupId = ext.cgroupId();
            lastPpid = ext.ppid();
            // Log at most ~1 in 256 non-zero observations to stay off the hot path.
            if ((logThrottle++ & 0xFF) == 0) {
                System.err.printf(
                        "[cgroup-aware] pid=%d cgroupId=%d ppid=%d%n",
                        t.pid, ext.cgroupId(), ext.ppid());
            }
        }
        return ANY_CPU;
    }

    @Override
    public String formatStats() {
        return String.format(
                "%s  observed=%d nonZeroCgroup=%d lastCgroupId=%d lastPpid=%d",
                super.formatStats(), observedTasks, nonZeroCgroup, lastCgroupId, lastPpid);
    }

    /** Number of tasks whose extension tail was read on the policy hot path. */
    public long observedTasks() {
        return observedTasks;
    }

    /** Number of observed tasks that carried a non-zero cgroup id (proves the BPF-side write). */
    public long nonZeroCgroup() {
        return nonZeroCgroup;
    }

    /** Most recently observed non-zero cgroup id. */
    public long lastCgroupId() {
        return lastCgroupId;
    }

    public static void main(String[] args) throws Exception {
        System.err.println(
                "CgroupAwareSample: attaching @TaskExtension demo scheduler (Ctrl-C to detach)...");
        new CgroupAwareSample().runUntilExit(new Opts());
    }
}
