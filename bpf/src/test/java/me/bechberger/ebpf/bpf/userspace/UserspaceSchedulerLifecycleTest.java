// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JVM-only state-machine test for {@link UserspaceScheduler} lifecycle.
 *
 * <p>Does NOT load a BPF program or require a sched_ext kernel. The BPF
 * load/attach and the {@code isAttached()} check are overridden to avoid
 * any kernel interaction, so this test runs on any JVM (including the mac
 * dev machine). Integration smoke tests (actual attach) live with the
 * sample schedulers in Task 18+.
 *
 * <p>This is the state-machine fallback variant described in the Task 10 spec:
 * "if integration is impractical, a state-machine-level test is the acceptable fallback."
 */
public class UserspaceSchedulerLifecycleTest {

    /**
     * Minimum-viable subclass: overrides BPF hooks to run without a kernel,
     * counts ticks, and returns ANY_CPU for everything.
     */
    static class NoopSched extends UserspaceScheduler {
        final AtomicInteger ticks = new AtomicInteger();
        final AtomicBoolean kernelAttached = new AtomicBoolean(true);

        @Override
        protected void tick() {
            ticks.incrementAndGet();
        }

        /** Skip BPF load/attach — we're testing Java-side state only. */
        @Override
        protected void loadAndAttachBpf() {
            // No-op: pretend we attached successfully.
        }

        /** Skip BPF close. */
        @Override
        protected void cleanupBpf() {
            // No-op.
        }

        /**
         * Simulate "kernel is attached" via a flag so the test can control when
         * the loop exits.
         */
        @Override
        protected boolean isAttached() {
            return kernelAttached.get();
        }

        /** Simulate kernel detach — loop will exit at next batch boundary. */
        void simulateKernelDetach() {
            kernelAttached.set(false);
        }
    }

    @Test
    @Timeout(15)
    void runUntilExitTerminatesOnRequest() throws InterruptedException {
        var sched = new NoopSched();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.setDaemon(true);
        runner.start();

        // Let the loop spin for at least two tick periods (≥ 2 s) to accumulate ticks.
        Thread.sleep(2000);

        sched.requestExit();
        runner.join(5000);

        assertFalse(runner.isAlive(), "runUntilExit did not return after requestExit");
        assertTrue(sched.ticks.get() >= 1, "tick() should have fired at least once during 2 s run");
        assertTrue(sched.exited(), "exited() must return true after runUntilExit returns");
    }

    @Test
    @Timeout(10)
    void runUntilExitTerminatesOnKernelDetach() throws InterruptedException {
        var sched = new NoopSched();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.setDaemon(true);
        runner.start();

        Thread.sleep(200);

        // Simulate the kernel detaching the scheduler (e.g. another scheduler
        // loaded, watchdog fired).
        sched.simulateKernelDetach();
        runner.join(5000);

        assertFalse(runner.isAlive(), "runUntilExit did not return after kernel detach");
        assertTrue(sched.exited(), "exited() must return true after runUntilExit returns");
    }

    @Test
    @Timeout(5)
    void exitedIsFalseBeforeRun() {
        var sched = new NoopSched();
        assertFalse(sched.exited(), "exited() must be false before runUntilExit is called");
    }

    @Test
    @Timeout(5)
    void requestExitBeforeStartCausesImmediateReturn() throws InterruptedException {
        var sched = new NoopSched();
        // Request exit before the thread even starts.
        sched.requestExit();

        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.setDaemon(true);
        runner.start();
        runner.join(3000);

        assertFalse(runner.isAlive(), "runUntilExit should return immediately when exit was pre-requested");
        assertTrue(sched.exited());
    }
}
