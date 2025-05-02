// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * A vtime scheduler that tries to schedule fairly.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "vtime_scheduler")
public abstract class VTimeScheduler extends BPFProgram
        implements Scheduler {

    // current vtime
    final GlobalVariable<@Unsigned Long> vtime_now =
            new GlobalVariable<>(0L);

    /*
     * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as
     * priority queues (meaning, cannot be dispatched to with
     * scx_bpf_dispatch_vtime()). We therefore create a
     * separate DSQ with ID 0 that we dispatch to and consume
     * from. If scx_simple only supported global FIFO scheduling,
     * then we could just use SCX_DSQ_GLOBAL.
     */
    static final long SHARED_DSQ_ID = 0;

    @BPFFunction
    @AlwaysInline
    boolean isSmaller(@Unsigned long a, @Unsigned long b) {
        return (long)(a - b) < 0;
    }

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu,
                         long wake_flags) {
        // same as before
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu,
                wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            scx_bpf_dispatch(p, SCX_DSQ_LOCAL.value(),
                    SCX_SLICE_DFL.value(),0);
        }
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        // get the weighted vtime, specified in the stopping
        // method
        @Unsigned long vtime = p.val().scx.dsq_vtime;

        /*
         * Limit the amount of budget that an idling task can
         * accumulate to one slice.
         */
        if (isSmaller(vtime,
                vtime_now.get() - SCX_SLICE_DFL.value())) {
            vtime = vtime_now.get() - SCX_SLICE_DFL.value();
        }
        /*
         * Dispatch the task to dsq_vtime-ordered priority
         * queue, which prioritizes tasks with smaller vtime
         */
        scx_bpf_dispatch_vtime(p, SHARED_DSQ_ID,
                SCX_SLICE_DFL.value(), vtime,
                enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_consume(SHARED_DSQ_ID);
    }

    @Override
    public void running(Ptr<task_struct> p) {
        /*
         * Global vtime always progresses forward as tasks
         * start executing. The test and update can be
         * performed concurrently from multiple CPUs and
         * thus racy. Any error should be contained and
         * temporary. Let's just live with it.
         */
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtime_now.get(), vtime)) {
            vtime_now.set(vtime);
        }
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        /*
         * Scale the execution time by the inverse of the weight
         * and charge.
         *
         * Note that the default yield implementation yields by
         * setting @p->scx.slice to zero and the following would
         * treat the yielding task
         * as if it has consumed all its slice. If this penalizes
         * yielding tasks too much, determine the execution time
         * by taking explicit timestamps instead of depending on
         * @p->scx.slice.
         */
        p.val().scx.dsq_vtime +=
                (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100
                        / p.val().scx.weight;
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        /*
         * Set the virtual time to the current vtime, when the task
         * is about to be scheduled for the first time
         */
        p.val().scx.dsq_vtime = vtime_now.get();
    }

    public static void main(String[] args) {
        try (var program =
                     BPFProgram.load(VTimeScheduler.class)) {
            program.attachScheduler();
            program.waitWhileSchedulerIsAttachedProperly();
        }
    }

}
