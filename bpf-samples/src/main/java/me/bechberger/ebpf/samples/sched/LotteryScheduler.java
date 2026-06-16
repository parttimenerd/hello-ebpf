package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Box;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_prandom_u32;

/** A lottery scheduler without priorities */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "lottery_scheduler")
public abstract class LotteryScheduler extends BPFProgram implements Scheduler {

    private static final int SHARED_DSQ_ID = 0;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
        int nr = scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        var sliceLength = nr > 0 ? ((@Unsigned int) 5_000_000) / nr : ((@Unsigned int) 5_000_000);
        scx_bpf_dsq_insert(p, SHARED_DSQ_ID, sliceLength, enq_flags);
    }

    /**
     * Pick a random task from the shared DSQ and move it to the calling CPU's local queue.
     *
     * <p>Uses {@link Scheduler#bpf_for_each_dsq} to scan the DSQ and
     * {@code scx_bpf_dsq_move} to move the winning task to the local CPU queue
     * without an affinity check (the kernel enforces affinity when the task is
     * actually scheduled).
     */
    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        int nr = scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        if (nr <= 0) {
            return;
        }
        Box<Integer> ticket = Box.of((int)(bpf_get_prandom_u32() % nr));
        Ptr<TaskDefinitions.task_struct> p = null;
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            ticket.set(ticket.val() - 1);
            if (ticket.val() <= 0) {
                scx_bpf_dsq_move(iter, p, SCX_DSQ_LOCAL.value(), 0);
                return;
            }
        });
    }

    public static void main(String[] args) throws Exception {
        try (LotteryScheduler scheduler = BPFProgram.load(LotteryScheduler.class)) {
            scheduler.runSchedulerLoop();
        }
    }
}
