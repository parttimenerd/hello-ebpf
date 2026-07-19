// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies {@link UserspaceScheduler#dispatchTask} fails fast with a self-explanatory
 * message on the two most common author mistakes: a null task and an out-of-range CPU.
 * Without these guards a bad CPU is silently rejected by the kernel and only shows up as
 * {@code SchedStatsSnapshot.dispatchFailed}, which is hard to diagnose.
 */
class DispatchTaskValidationTest {

    /** Minimal concrete scheduler; dispatchTask is inherited and does not touch BPF here. */
    static final class Sched extends FakeSchedulerBase {}

    private QueuedTask task(int pid) {
        var t = new QueuedTask();
        t.pid = pid;
        return t;
    }

    @Test
    void nullTaskThrowsHelpfulNpe() {
        var sched = new Sched();
        var ex = assertThrows(NullPointerException.class, () -> sched.dispatchTask(null, UserspaceScheduler.ANY_CPU));
        assertTrue(ex.getMessage().contains("copy()"),
                "message should point authors at QueuedTask.copy(): " + ex.getMessage());
    }

    @Test
    void negativeNonAnyCpuThrows() {
        var sched = new Sched();
        var ex = assertThrows(IllegalArgumentException.class, () -> sched.dispatchTask(task(42), -7));
        assertTrue(ex.getMessage().contains("out of range") && ex.getMessage().contains("42"),
                "message should name the bad cpu and pid: " + ex.getMessage());
    }

    @Test
    void hugeCpuIndexThrows() {
        var sched = new Sched();
        int tooBig = Runtime.getRuntime().availableProcessors() + 1000;
        var ex = assertThrows(IllegalArgumentException.class, () -> sched.dispatchTask(task(9), tooBig));
        assertTrue(ex.getMessage().contains("ANY_CPU"),
                "message should suggest ANY_CPU as the fix: " + ex.getMessage());
    }

    @Test
    void anyCpuIsAlwaysAccepted() {
        var sched = new Sched();
        // Should not throw; submitDispatch is stubbed to succeed in FakeSchedulerBase.
        assertDoesNotThrow(() -> sched.dispatchTask(task(1), UserspaceScheduler.ANY_CPU));
    }

    @Test
    void validCpuZeroIsAccepted() {
        var sched = new Sched();
        assertDoesNotThrow(() -> sched.dispatchTask(task(1), 0));
    }
}
