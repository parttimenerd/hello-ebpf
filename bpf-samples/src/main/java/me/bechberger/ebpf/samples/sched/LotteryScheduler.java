package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.runtime.BpfDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.type.Box;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_cpumask_test_cpu;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dispatch_from_dsq;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL_ON;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_enq_flags.SCX_ENQ_PREEMPT;
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
        var sliceLength = ((@Unsigned int) 5_000_000) / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        scx_bpf_dispatch(p, SHARED_DSQ_ID, sliceLength, enq_flags);
    }

    @BPFFunction
    @AlwaysInline
    public boolean tryDispatching(Ptr<BpfDefinitions.bpf_iter_scx_dsq> iter, Ptr<TaskDefinitions.task_struct> p, int cpu) {
        // check if the CPU is usable by the task
        if (!bpf_cpumask_test_cpu(cpu, p.val().cpus_ptr)) {
            return false;
        }
        return scx_bpf_dispatch_from_dsq(iter, p, SCX_DSQ_LOCAL_ON.value() | cpu, SCX_ENQ_PREEMPT.value());
    }

    /**
     * Dispatch tasks
     * <p/>
     * Pick a random task from the shared DSQ and try to dispatch it
     */
    @Override
    public void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) {
        Box<Integer> random = Box.of(bpf_get_prandom_u32() % scx_bpf_dsq_nr_queued(SHARED_DSQ_ID));
        Ptr<TaskDefinitions.task_struct> p = null;
        bpf_for_each_dsq(SHARED_DSQ_ID, p, iter -> {
            random.set(random.val() - 1);
            if (random.val() <= 0 && tryDispatching(iter, p, cpu)) {
                return;
            }
        });
    }

    public static void main(String[] args) throws Exception {
        try (LotteryScheduler scheduler = BPFProgram.load(LotteryScheduler.class)) {
            scheduler.attachScheduler();
            while (scheduler.isSchedulerAttachedProperly()) {
                Thread.sleep(1000);
            }
        }
    }
}