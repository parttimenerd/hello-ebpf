package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_prandom_u32;

/**
 * A lottery scheduler: each task receives a random time slice, simulating
 * lottery scheduling by biasing dispatch order through slice length.
 *
 * <p>This is an original Java/sched_ext implementation.  The lottery scheduling
 * concept is described in
 * <a href="https://www.usenix.org/conference/osdi-94/lottery-and-stride-scheduling-flexible-proportional-share-resource-management">
 * Waldspurger &amp; Weihl, OSDI '94</a>.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "lottery_scheduler")
public abstract class LotteryScheduler extends BPFProgram implements Scheduler {

    private static final int SHARED_DSQ_ID = 0;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    /**
     * Assign each task a random time slice proportional to its lottery ticket.
     * Tasks with more tickets (higher random value) get more CPU time — simulating
     * a lottery by biasing the scheduling order via slice length.
     */
    @Override
    public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
        int nr = scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        // Random slice: up to 10ms, scaled down if queue is large to avoid starvation.
        int maxSlice = 10_000_000;
        int sliceLength = nr > 0 ? ((@Unsigned int) (bpf_get_prandom_u32() % maxSlice)) / nr
                                 : ((@Unsigned int) (bpf_get_prandom_u32() % maxSlice));
        if (sliceLength == 0) {
            sliceLength = 1_000_000;
        }
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, sliceLength, enq_flags);
    }

    /**
     * Move the next eligible task from the shared DSQ to the local CPU queue.
     * {@code scx_bpf_dsq_move_to_local} respects CPU affinity, so constrained
     * tasks (kworkers, isolated CPUs) are skipped automatically.
     */
    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    public static void main(String[] args) throws Exception {
        try (LotteryScheduler scheduler = BPFProgram.load(LotteryScheduler.class)) {
            scheduler.runSchedulerLoop();
        }
    }
}
