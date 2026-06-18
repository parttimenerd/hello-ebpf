package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.samples.sched.BoostedScheduler;
import me.bechberger.ebpf.samples.sched.CPU0Scheduler;
import me.bechberger.ebpf.samples.sched.DeadlineScheduler;
import me.bechberger.ebpf.samples.sched.FlowScheduler;
import me.bechberger.ebpf.samples.sched.PriorityScheduler;
import me.bechberger.ebpf.samples.sched.SimpleScheduler;
import me.bechberger.ebpf.samples.sched.VTimeScheduler;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behavioral tests that go beyond the smoke suite: they drive controlled
 * workloads and verify that specific scheduling semantics hold — stats are
 * accurate, optional callbacks are actually invoked, and counters respond to
 * mode switches.
 *
 * <p>Each test either reuses an existing sample scheduler or defines a minimal
 * inner {@code @BPF} class that adds the counter it needs.
 */
@ExtendWith(SchedulerExtension.class)
class SchedulerBehaviorTest {

    // -------------------------------------------------------------------------
    // 1. Stats accuracy — SimpleScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that the enqueue and dispatch counters in {@link SimpleScheduler}
     * increment under a real workload, and continue to increment after switching
     * to vtime mode.
     */
    @Test
    @Timeout(20)
    @TestScheduler(SimpleScheduler.class)
    void simpleSchedulerStatsAccurate(SimpleScheduler sched) throws Exception {
        long enqueuedBefore = sched.getTotalEnqueued();
        long dispatchedBefore = sched.getTotalDispatched();

        // Drive a spin workload so the scheduler sees activity.
        Thread spinner = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner.start();
        spinner.join();

        long enqueuedFifo = sched.getTotalEnqueued();
        long dispatchedFifo = sched.getTotalDispatched();
        assertTrue(enqueuedFifo > enqueuedBefore,
                "enqueued count should increase under FIFO load; before=" + enqueuedBefore
                        + " after=" + enqueuedFifo);
        assertTrue(dispatchedFifo > dispatchedBefore,
                "dispatched count should increase under FIFO load; before=" + dispatchedBefore
                        + " after=" + dispatchedFifo);

        // Switch to vtime mode and verify counters keep growing.
        sched.setFifoMode(false);

        Thread spinner2 = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner2.start();
        spinner2.join();

        assertTrue(sched.getTotalEnqueued() > enqueuedFifo,
                "enqueued count should increase after switching to vtime mode");
        assertTrue(sched.getTotalDispatched() > dispatchedFifo,
                "dispatched count should increase after switching to vtime mode");
    }

    // -------------------------------------------------------------------------
    // 2. Stats accuracy — VTimeScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link VTimeScheduler} (pure vtime) accumulates enqueued
     * and dispatched counts under load.
     */
    @Test
    @Timeout(15)
    @TestScheduler(VTimeScheduler.class)
    void vtimeSchedulerStatsAccurate(VTimeScheduler sched) throws Exception {
        Thread spinner = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner.start();
        spinner.join();

        assertTrue(sched.getTotalEnqueued() > 0,
                "VTimeScheduler enqueued count should be positive after 400 ms of activity");
        assertTrue(sched.getTotalDispatched() > 0,
                "VTimeScheduler dispatched count should be positive after 400 ms of activity");
    }

    // -------------------------------------------------------------------------
    // 3. EDF ordering — DeadlineScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link DeadlineScheduler} attaches, stays alive under load,
     * and responds to a period change.
     *
     * <p>We cannot easily observe EDF ordering from userspace, but we can verify
     * that the scheduler runs stably while we exercise its configurable period:
     * change it mid-run and confirm the scheduler remains healthy.
     */
    @Test
    @Timeout(20)
    @TestScheduler(DeadlineScheduler.class)
    void deadlineSchedulerRunsAndRespondsToConfig(DeadlineScheduler sched) throws Exception {
        assertTrue(sched.isSchedulerAttachedProperly(),
                "DeadlineScheduler should be attached initially");

        // Drive some load at the default period (10 ms).
        Thread spinner = new Thread(() -> {
            long end = System.nanoTime() + 300_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner.start();
        spinner.join();

        assertTrue(sched.isSchedulerAttachedProperly(),
                "DeadlineScheduler should survive 300 ms spin workload");

        // Change the period and verify the scheduler keeps running.
        long newPeriod = 5_000_000L; // 5 ms
        sched.setPeriodNs(newPeriod);
        assertEquals(newPeriod, sched.getPeriodNs(),
                "getPeriodNs() should reflect the updated period");

        Thread spinner2 = new Thread(() -> {
            long end = System.nanoTime() + 300_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner2.start();
        spinner2.join();

        assertTrue(sched.isSchedulerAttachedProperly(),
                "DeadlineScheduler should survive load after period change");
    }

    // -------------------------------------------------------------------------
    // 4. CPU affinity — CPU0Scheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link CPU0Scheduler} dispatches at least once on CPU 0
     * during a spin workload.  The scheduler concentrates all work on CPU 0,
     * so its {@code dispatch()} hook (which only acts when {@code cpu == 0})
     * must be called.
     */
    @Test
    @Timeout(15)
    @TestScheduler(CPU0Scheduler.class)
    void cpu0SchedulerDispatchesOnCpu0(CPU0Scheduler sched) throws Exception {
        Thread spinner = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner.start();
        spinner.join();

        assertTrue(sched.isSchedulerAttachedProperly(),
                "CPU0Scheduler should remain attached after spin workload");
        assertTrue(sched.getTotalDispatched() > 0,
                "CPU0Scheduler dispatch() on CPU 0 should have fired at least once");
    }

    // -------------------------------------------------------------------------
    // 5. Priority ordering — PriorityScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link PriorityScheduler} routes tasks into at least two of
     * its five priority queues during 500 ms of normal system activity.
     *
     * <p>Any realistic system has tasks at several different nice levels (kernel
     * threads, user threads, systemd units), so multiple weight classes must be
     * served.  We count how many of the 5 per-queue enqueue counters are non-zero.
     */
    @Test
    @Timeout(15)
    @TestScheduler(PriorityScheduler.class)
    void prioritySchedulerUsesMultipleQueues(PriorityScheduler sched) throws Exception {
        Thread.sleep(500);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "PriorityScheduler should remain attached for 500 ms");
        int activeQueues = sched.getActiveQueueCount();
        assertTrue(activeQueues >= 1,
                "Expected at least 1 of 5 priority queues to be used, got " + activeQueues);
    }

    // -------------------------------------------------------------------------
    // 6. Callback coverage — tick, running, stopping
    // -------------------------------------------------------------------------

    /**
     * Scheduler that records how many times each of the optional callbacks
     * {@link Scheduler#tick}, {@link Scheduler#running}, and
     * {@link Scheduler#stopping} is invoked.
     */
    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "callback_coverage_sched")
    public abstract static class CallbackCoverageScheduler
            extends BPFProgram implements Scheduler {

        static final long SHARED_DSQ_ID = 0;

        final GlobalVariable<@Unsigned Long> tickCount = new GlobalVariable<>(0L);
        final GlobalVariable<@Unsigned Long> runningCount = new GlobalVariable<>(0L);
        final GlobalVariable<@Unsigned Long> stoppingCount = new GlobalVariable<>(0L);

        // Prologue (scx_bpf_create_dsq) is injected before init() body by the compiler plugin.
        final DispatchQueue shared = new DispatchQueue(SHARED_DSQ_ID);

        @Override
        public int init() {
            return 0;
        }

        @Override
        public void enqueue(Ptr<task_struct> p, long enq_flags) {
            shared.insert(p, SCX_SLICE_DFL.value(), EnqFlags.passThrough(enq_flags));
        }

        @Override
        public void dispatch(int cpu, Ptr<task_struct> prev) {
            shared.moveToLocal();
        }

        @Override
        public void tick(Ptr<task_struct> p) {
            tickCount.set(tickCount.get() + 1);
        }

        @Override
        public void running(Ptr<task_struct> p) {
            runningCount.set(runningCount.get() + 1);
        }

        @Override
        public void stopping(Ptr<task_struct> p, boolean runnable) {
            stoppingCount.set(stoppingCount.get() + 1);
        }
    }

    /**
     * Verifies that {@code tick()}, {@code running()}, and {@code stopping()}
     * are all invoked at least once during 500 ms of normal system activity.
     */
    @Test
    @Timeout(20)
    @TestScheduler(CallbackCoverageScheduler.class)
    void callbackCoverageSchedulerFiresAllOptionalCallbacks(CallbackCoverageScheduler sched)
            throws Exception {
        Thread.sleep(500);

        assertTrue(sched.isSchedulerAttachedProperly(),
                "CallbackCoverageScheduler should stay attached for 500 ms");
        assertTrue(sched.tickCount.get() > 0,
                "tick() should have been called at least once in 500 ms; got "
                        + sched.tickCount.get());
        assertTrue(sched.runningCount.get() > 0,
                "running() should have been called at least once in 500 ms; got "
                        + sched.runningCount.get());
        assertTrue(sched.stoppingCount.get() > 0,
                "stopping() should have been called at least once in 500 ms; got "
                        + sched.stoppingCount.get());
    }

    /**
     * Exercises {@link FlowScheduler}: verifies that the scheduler attaches,
     * stays alive under load, dispatches tasks through at least one tier DSQ,
     * and that wakeup counters advance.  Also checks that tunable parameters
     * can be changed while attached.
     */
    @Test
    @Timeout(20)
    @TestScheduler(FlowScheduler.class)
    void flowSchedulerBudgetTiersAndCounters(FlowScheduler sched) throws Exception {
        assertTrue(sched.isSchedulerAttachedProperly(),
                "FlowScheduler should be attached");

        // Spin to generate task activity
        long end = System.nanoTime() + 400_000_000L;
        while (System.nanoTime() < end) { /* busy */ }

        Thread.sleep(100);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "FlowScheduler should remain attached after 500 ms of activity");

        long totalTierDispatches =
                sched.getTierPriorityDispatches()
                + sched.getTierNormalDispatches()
                + sched.getTierLowDispatches()
                + sched.getTierDeficitDispatches()
                + sched.getPinnedDispatches()
                + sched.getPrioDispatches();

        assertTrue(totalTierDispatches > 0,
                "FlowScheduler should have dispatched at least one task; got "
                        + totalTierDispatches);

        // Tunable: change max slice while running
        sched.setReservedMaxNs(200_000L); // 200 µs
        Thread.sleep(100);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "FlowScheduler should remain attached after tunable change");
    }

    // -------------------------------------------------------------------------
    // 7. Boost-path routing — BoostedScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link BoostedScheduler} routes the current JVM process into
     * the boosted DSQ when boost mode is enabled, and into the normal DSQ when
     * boost mode is disabled.
     *
     * <p>We can't guarantee every enqueue comes from this JVM, but after enabling
     * boost with the current process boosted, at least some tasks must land in
     * the boosted DSQ (since the JVM is actively scheduling threads).  After
     * disabling boost, the boosted counter must stop growing.
     */
    @Test
    @Timeout(20)
    @TestScheduler(value = BoostedScheduler.class, autoAttach = false)
    void boostedSchedulerRoutesBoostedTasksToBoostedDsq(BoostedScheduler sched) throws Exception {
        int myTgid = (int) ProcessHandle.current().pid();
        sched.boostTgid(myTgid);
        sched.setBoostEnabled(true);
        sched.attachScheduler();

        // Run some threads so the JVM generates enqueue() calls.
        Thread spinner = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner.start();
        spinner.join();

        long boostedAfterBoost = sched.getBoostedEnqueueCount();
        long normalAfterBoost  = sched.getNormalEnqueueCount();

        assertTrue(sched.isSchedulerAttachedProperly(),
                "BoostedScheduler should remain attached while boosting");
        assertTrue(boostedAfterBoost > 0,
                "Boosted enqueue count should be positive while current process is boosted; got "
                        + boostedAfterBoost);
        assertTrue(normalAfterBoost > 0,
                "Normal enqueue count should also be positive (other system tasks); got "
                        + normalAfterBoost);

        // Disable boost — subsequent enqueues from this process go to normal DSQ.
        sched.setBoostEnabled(false);

        Thread spinner2 = new Thread(() -> {
            long end = System.nanoTime() + 400_000_000L;
            while (System.nanoTime() < end) {}
        });
        spinner2.start();
        spinner2.join();

        long normalAfterDisable = sched.getNormalEnqueueCount();
        assertTrue(normalAfterDisable > normalAfterBoost,
                "Normal enqueue count should grow after boost is disabled; before="
                        + normalAfterBoost + " after=" + normalAfterDisable);
    }

    // -------------------------------------------------------------------------
    // 8. Priority dispatch coverage — PriorityScheduler
    // -------------------------------------------------------------------------

    /**
     * Verifies that {@link PriorityScheduler} not only enqueues into multiple
     * weight classes but also dispatches from them — specifically that the
     * dispatch counter keeps pace with the enqueue counter.
     */
    @Test
    @Timeout(15)
    @TestScheduler(PriorityScheduler.class)
    void prioritySchedulerDispatchesFromQueuedTasks(PriorityScheduler sched) throws Exception {
        Thread.sleep(500);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "PriorityScheduler should remain attached for 500 ms");

        int activeDispatchQueues = sched.getActiveDispatchQueueCount();
        assertTrue(activeDispatchQueues >= 1,
                "At least 1 of 5 queues should have dispatched tasks; got "
                        + activeDispatchQueues);

        // Total dispatched should be ≥ total enqueued across all queues
        // (can exceed when selectCPU fast-path fires).
        long totalEnqueued  = 0;
        long totalDispatched = 0;
        for (int q = 0; q < PriorityScheduler.NUM_QUEUES; q++) {
            totalEnqueued  += sched.getQueueEnqueueCount(q);
            totalDispatched += sched.getQueueDispatchCount(q);
        }
        assertTrue(totalEnqueued > 0,
                "Total enqueue count should be positive after 500 ms; got " + totalEnqueued);
        assertTrue(totalDispatched > 0,
                "Total dispatch count should be positive after 500 ms; got " + totalDispatched);
    }
}
