// SPDX-License-Identifier: GPL-2.0
// See license at
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.h
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_userland.bpf.c

package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.bpf.BPFJ;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.bpf.map.BPFQueue;
import me.bechberger.ebpf.bpf.raw.Lib;
import me.bechberger.ebpf.bpf.raw.Lib_1;
import me.bechberger.ebpf.bpf.raw.sched_param;
import me.bechberger.ebpf.runtime.helpers.BPFHelpers;
import me.bechberger.ebpf.type.Ptr;
import picocli.CommandLine;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import static me.bechberger.ebpf.bpf.raw.Lib_1.sched_get_priority_max;
import static me.bechberger.ebpf.bpf.raw.Lib_1.sched_setscheduler;
import static me.bechberger.ebpf.bpf.raw.Lib_2.bpf_link__destroy;
import static me.bechberger.ebpf.bpf.raw.Lib_2.bpf_map__attach_struct_ops;
import static me.bechberger.ebpf.bpf.raw.Lib_3.*;
import static picocli.CommandLine.*;

import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_task_from_pid;
import static me.bechberger.ebpf.runtime.BpfDefinitions.bpf_task_release;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_GLOBAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;

@BPF(license = "GPL")
public abstract class SampleScheduler extends BPFProgram implements Scheduler, Runnable {

    /*
     * An instance of a task that has been enqueued by the kernel for consumption
     * by a user space global scheduler thread.
     */
    @Type
    static class scx_userland_enqueued_task {
        int pid;
        @Unsigned long sum_exec_runtime;
        @Unsigned long weight;
    }

    /*
     * Maximum amount of tasks enqueued/dispatched between kernel and user-space.
     */
    static final int MAX_ENQUEUED_TASKS = 4096;

    final GlobalVariable<Integer> usersched_pid = new GlobalVariable<>(0);

    /* !0 for veristat, set during init */
    final GlobalVariable<Integer> num_possible_cpus = new GlobalVariable<>(64);

    /* Stats that are printed by user space. */
    final GlobalVariable<Long> nr_failed_enqueues = new GlobalVariable<>(0L);
    final GlobalVariable<Long> nr_kernel_enqueues = new GlobalVariable<>(0L);
    final GlobalVariable<Long> nr_user_enqueues = new GlobalVariable<>(0L);

    /*
     * Number of tasks that are queued for scheduling.
     *
     * This number is incremented by the BPF component when a task is queued to the
     * user-space scheduler and it must be decremented by the user-space scheduler
     * when a task is consumed.
     */
    final GlobalVariable<Long> nr_queued = new GlobalVariable<>(0L);


    /*
     * Number of tasks that are waiting for scheduling.
     *
     * This number must be updated by the user-space scheduler to keep track if
     * there is still some scheduling work to do.
     */
    final GlobalVariable<Long> nr_scheduled = new GlobalVariable<>(0L);

    // we skip the exit info here, because we need it here

    /*
     * The map containing tasks that are enqueued in user space from the kernel.
     *
     * This map is drained by the user space scheduler.
     */
    @BPFMapDefinition(maxEntries = MAX_ENQUEUED_TASKS)
    BPFQueue<scx_userland_enqueued_task> enqueued;

    /*
     * The map containing tasks that are dispatched to the kernel from user space.
     *
     * Drained by the kernel in userland_dispatch().
     */
    @BPFMapDefinition(maxEntries = MAX_ENQUEUED_TASKS)
    BPFQueue<Integer> dispatched;

    /* Per-task scheduling context */
    @Type
    static class task_ctx {
        boolean force_local;
    }

    // we ignore the force_local for now
    /* Map that contains task-local storage. */
    /*struct {
        __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __type(key, int);
        __type(value, struct task_ctx);
    } task_ctx_stor SEC(".maps");*/

    @BPFMapDefinition(maxEntries = 1000000)
    BPFLRUHashMap<@Unsigned Integer, task_ctx> task_ctx_stor;

    final GlobalVariable<@Unsigned Long> usersched_needed = new GlobalVariable<>(0L);

    /**
     * Set user-space scheduler wake-up flag (equivalent to an atomic release
     * operation).
     */
    @BPFFunction
    void set_usersched_needed() {
        BPFJ.sync_fetch_and_or(Ptr.of(usersched_needed.get()), 1);
    }

    /**
     * Check and clear user-space scheduler wake-up flag (equivalent to an atomic
     * acquire operation).
     */
    @BPFFunction
    boolean test_and_clear_usersched_needed() {
        return BPFJ.sync_fetch_and_and(Ptr.of(usersched_needed.get()), 0L) == 1L;
    }

    @BPFFunction
    boolean is_usersched_task(int pid) {
        return pid == usersched_pid.get();
    }

    @BPFFunction
    boolean keep_in_kernel(int nr_cpus_allowed) {
        return nr_cpus_allowed < num_possible_cpus.get();
    }

    /** Get the scheduler task */
    @BPFFunction
    Ptr<task_struct> usersched_task() {
        Ptr<task_struct> p = bpf_task_from_pid(usersched_pid.get());

        /*
         * Should never happen -- the usersched task should always be managed
         * by sched_ext.
         */

        if (p == null) {
            scx_bpf_error("Failed to find usersched task %d", usersched_pid.get());
        }
        return p;
    }

    @Override
    public int userland_select_cpu(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        if (keep_in_kernel(p.val().nr_cpus_allowed)) {
            int cpu;
            Ptr<task_ctx> tctx = task_ctx_stor.bpf_get(p.val().pid);
            if (tctx == null) {
                scx_bpf_error("Failed to look up task-local storage for %s", p.val().comm);
                return -ESRCH;
            }
            if (p.val().nr_cpus_allowed == 1 || scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
                tctx.val().force_local = true;
                return prev_cpu;
            }
            cpu = scx_bpf_pick_idle_cpu(p.val().cpus_ptr, 0);
            if (cpu >= 0) {
                tctx.val().force_local = true;
                return cpu;
            }
        }
        return prev_cpu;
    }

    @BPFFunction
    void dispatch_user_scheduler() {
        Ptr<task_struct> p = usersched_task();
        if (p != null) {
            scx_bpf_dispatch(p, SCX_DSQ_GLOBAL.value(), SCX_SLICE_DFL.value(), 0);
            bpf_task_release(p);
        }
    }

    @BPFFunction
    void enqueue_task_in_user_space(Ptr<task_struct> p, long enq_flags) {
        scx_userland_enqueued_task task = new scx_userland_enqueued_task();
        task.pid = p.val().pid;
        task.sum_exec_runtime = p.val().se.sum_exec_runtime;
        task.weight = p.val().scx.weight;
        if (enqueued.push(task)) {
            /*
             * If we fail to enqueue the task in user space, put it
             * directly on the global DSQ.
             */
            BPFJ.sync_fetch_and_add(Ptr.of(nr_failed_enqueues.get()), 1L);
            scx_bpf_dispatch(p, SCX_DSQ_GLOBAL.value(), SCX_SLICE_DFL.value(), enq_flags);
        } else {
            BPFJ.sync_fetch_and_add(Ptr.of(nr_user_enqueues.get()), 1L);
            set_usersched_needed();
        }
    }

    @Override
    public void userland_enqueue(Ptr<task_struct> p, long enq_flags) {
        if (keep_in_kernel(p.val().nr_cpus_allowed)) {
            long dsq_id = SCX_DSQ_GLOBAL.value();
            Ptr<task_ctx> tctx = task_ctx_stor.bpf_get(p.val().pid);
            if (tctx == null) {
                scx_bpf_error("Failed to lookup task ctx for %s", p.val().comm);
                return;
            }
            if (tctx.val().force_local) {
                dsq_id = SCX_DSQ_LOCAL.value();
            }
            tctx.val().force_local = false;
            scx_bpf_dispatch(p, dsq_id, SCX_SLICE_DFL.value(), enq_flags);
            BPFJ.sync_fetch_and_add(Ptr.of(nr_kernel_enqueues.get()), 1L);
            return;
        } else if (!is_usersched_task(p.val().pid)) {
            enqueue_task_in_user_space(p, enq_flags);
        }
    }

    @Override
    public void userland_dispatch(int cpu, Ptr<task_struct> prev) {
        if (test_and_clear_usersched_needed()) {
            dispatch_user_scheduler();
        }
        for (int i = 0; i < MAX_ENQUEUED_TASKS; i++) {
            Integer pid = 0;
            if (!dispatched.bpf_pop(pid)) {
                break;
            }
            /*
             * The task could have exited by the time we get around to
             * dispatching it. Treat this as a normal occurrence, and simply
             * move onto the next iteration.
             */
            Ptr<task_struct> p = bpf_task_from_pid(pid);
            if (p == null) {
                continue;
            }
            scx_bpf_dispatch(p, SCX_DSQ_GLOBAL.value(), SCX_SLICE_DFL.value(), 0);
            bpf_task_release(p);
        }
    }

    public void userland_update_idle(int cpu, boolean idle) {
        /*
         * Don't do anything if we exit from and idle state, a CPU owner will
         * be assigned in .running().
         */
        if (!idle) {
            return;
        }
        /*
         * A CPU is now available, notify the user-space scheduler that tasks
         * can be dispatched, if there is at least one task waiting to be
         * scheduled, either queued (accounted in nr_queued) or scheduled
         * (accounted in nr_scheduled).
         *
         * NOTE: nr_queued is incremented by the BPF component, more exactly in
         * enqueue(), when a task is sent to the user-space scheduler, then
         * the scheduler drains the queued tasks (updating nr_queued) and adds
         * them to its internal data structures / state; at this point tasks
         * become "scheduled" and the user-space scheduler will take care of
         * updating nr_scheduled accordingly; lastly tasks will be dispatched
         * and the user-space scheduler will update nr_scheduled again.
         *
         * Checking both counters allows to determine if there is still some
         * pending work to do for the scheduler: new tasks have been queued
         * since last check, or there are still tasks "queued" or "scheduled"
         * since the previous user-space scheduler run. If the counters are
         * both zero it is pointless to wake-up the scheduler (even if a CPU
         * becomes idle), because there is nothing to do.
         *
         * Keep in mind that update_idle() doesn't run concurrently with the
         * user-space scheduler (that is single-threaded): this function is
         * naturally serialized with the user-space scheduler code, therefore
         * this check here is also safe from a concurrency perspective.
         */
        if (nr_queued.get() != 0 || nr_scheduled.get() != 0) {
            set_usersched_needed();
            scx_bpf_kick_cpu(cpu, 0);
        }
    }

    @Override
    public int userland_init_task(Ptr<task_struct> p, Ptr<scx_init_task_args> args) {
        if (task_ctx_stor.bpf_get(p.val().pid) == null) {
            return 0;
        } else {
            return -ENOMEM();
        }
    }

    @Override
    public int userland_init() {
        if (num_possible_cpus.get() == 0) {
            scx_bpf_error("User scheduler # CPUs uninitialized (%d)", num_possible_cpus.get());
            return -EINVAL();
        }

        if (usersched_pid.get() <= 0) {
            scx_bpf_error("User scheduler pid uninitialized (%d)", usersched_pid.get());
            return -EINVAL();
        }

        return 0;
    }

    @Override
    public void userland_exit(Ptr<scx_exit_info> ei) {
        scx_bpf_error("Userland scheduler exited %s", ei.val().msg);
    }

    // user land part

    /* Number of tasks to batch when dispatching to user space. */
    @Option(names = "--batch-size", defaultValue = "8",
            description = "Number of tasks to batch when dispatching to user space")
    final int batch_size = 8;

    @Option(names = "--verbose")
    boolean verbose = false;

    // no sigint handler

    /* stats collected in user space */
    long nr_vruntime_enqueues;
    long nr_vruntime_dispatches;
    long nr_vruntime_failed;

    double min_vruntime = 0.0;

    /** Number of tasks currently enqueued */
    long nr_curr_enqueued;

    AtomicBoolean shouldStop = new AtomicBoolean(false);

    MemorySegment opsLink;

    /* The data structure containing tasks that are enqueued in user space. */
    static final class enqueued_task {
        int pid;
        long sum_exec_runtime;
        double vruntime;

        enqueued_task(int pid, long sum_exec_runtime, double vruntime) {
            this.pid = pid;
            this.sum_exec_runtime = sum_exec_runtime;
            this.vruntime = vruntime;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == this) return true;
            if (obj == null || obj.getClass() != this.getClass()) return false;
            var that = (enqueued_task) obj;
            return this.pid == that.pid &&
                    this.sum_exec_runtime == that.sum_exec_runtime &&
                    Double.doubleToLongBits(this.vruntime) == Double.doubleToLongBits(that.vruntime);
        }

        @Override
        public int hashCode() {
            return Objects.hash(pid, sum_exec_runtime, vruntime);
        }

        @Override
        public String toString() {
            return "enqueued_task[" +
                    "pid=" + pid + ", " +
                    "sum_exec_runtime=" + sum_exec_runtime + ", " +
                    "vruntime=" + vruntime + ']';
        }
    }

    /* we don't preallocate here, so this might cause deadlocks, but we're ignoring this here */
    List<enqueued_task> enqueued_tasks = new ArrayList<>();

    int pidMax = Scheduler.getPidMax();

    enqueued_task[] tasks = new enqueued_task[pidMax];

    /** Dispatch a specific task via the dispatch queue */
    boolean dispatch_task(int pid) {
        if (dispatched.push(pid)) {
            nr_vruntime_failed += 1;
            return true;
        } else {
            nr_vruntime_dispatches += 1;
            return false;
        }
    }

    /** Get a task for the given id or null */
    enqueued_task get_enqueued_task(int pid) {
        if (pid < 0 || pid >= pidMax) {
            return null;
        }
        return tasks[pid];
    }


    /**
     * Compute weighted delta
     *
     * @param weight the weight of the task
     * @param delta the time delta to compute the vruntime for
     */
    double calc_vruntime_delta(long weight, long delta) {
        double weight_f = (double) weight / 100.0;
        double delta_f = (double) delta;

        return delta_f / weight_f;
    }

    void update_enqueued(enqueued_task enqueued, scx_userland_enqueued_task bpf_task) {
        long delta = bpf_task.sum_exec_runtime - enqueued.sum_exec_runtime;

        enqueued.vruntime += calc_vruntime_delta(bpf_task.weight, delta);
        if (min_vruntime > enqueued.vruntime) {
            enqueued.vruntime = min_vruntime;
        }
        enqueued.sum_exec_runtime = bpf_task.sum_exec_runtime;
    }

    /** Enqueue a task in the user space queue */
    int vruntime_enqueue(scx_userland_enqueued_task bpf_task) {
        enqueued_task curr = get_enqueued_task(bpf_task.pid);
        if (curr == null) {
            return ENOENT();
        }

        update_enqueued(curr, bpf_task);
        nr_vruntime_enqueues++;
        nr_curr_enqueued++;


        /*
         * Enqueue the task in a vruntime-sorted list. A more optimal data
         * structure such as an rbtree could easily be used as well. We elect
         * to use a list here simply because it's less code, and thus the
         * example is less convoluted and better serves to illustrate what a
         * user space scheduler could look like.
         */

        if (enqueued_tasks.isEmpty()) {
            enqueued_tasks.add(curr);
        } else {
            int i = 0;
            for (; i < enqueued_tasks.size(); i++) {
                if (enqueued_tasks.get(i).vruntime > curr.vruntime) {
                    break;
                }
            }
            enqueued_tasks.add(i, curr);
        }
        return 0;
    }

    /**
     * Drain the enqueued map from kernel land into the user land queue
     */
    void drain_enqueued_map() {
        while (true) {
            scx_userland_enqueued_task task = enqueued.pop();
            if (task == null) {
                nr_queued.set(0L);
                nr_scheduled.set(nr_curr_enqueued);
                return;
            }

            int err = vruntime_enqueue(task);
            if (err != 0) {
                System.err.println("Failed to enqueue task " + task.pid);
                shouldStop.set(true);
                return;
            }
        }
    }


    void dispatch_batch() {
        for (int i = 0; i < batch_size; i++) {
            if (enqueued_tasks.isEmpty()) {
                break;
            }
            enqueued_task task = enqueued_tasks.removeFirst();
            min_vruntime = task.vruntime;
            if (dispatch_task(task.pid)) {
                /*
                 * If we fail to dispatch, put the task back to the
                 * vruntime_head list and stop dispatching additional
                 * tasks in this batch.
                 */
                enqueued_tasks.addFirst(task);
                break;
            }
            nr_curr_enqueued--;
        }
        nr_scheduled.set(nr_curr_enqueued);
    }

    void runStatsLoop() {
        long nr_failed_enqueues, nr_kernel_enqueues, nr_user_enqueues, total;
        nr_failed_enqueues = this.nr_failed_enqueues.get();
        nr_kernel_enqueues = this.nr_kernel_enqueues.get();
        nr_user_enqueues = this.nr_user_enqueues.get();
        total = nr_failed_enqueues + nr_kernel_enqueues + nr_user_enqueues;
        System.out.printf("""
                o-----------------------o
                | BPF ENQUEUES          |
                |-----------------------|
                |  kern:     %10d |
                |  user:     %10d |
                |  failed:   %10d |
                |  -------------------- |
                |  total:    %10d |
                |                       |
                |-----------------------|
                | VRUNTIME / USER       |
                |-----------------------|
                |  enq:      %10d |
                |  disp:     %10d |
                |  failed:   %10d |
                o-----------------------o
                """, nr_kernel_enqueues, nr_user_enqueues, nr_failed_enqueues,
                total, nr_vruntime_enqueues, nr_vruntime_dispatches, nr_vruntime_failed);
    }

    void initTasks() {
        for (int i = 0; i < pidMax; i++) {
            tasks[i] = new enqueued_task(i, 0, 0.0);
        }
    }

    void set_scheduler() {
        var sm = sched_param.allocate(Arena.global());
        var maxPriority = sched_get_priority_max(SCHED_EXT_UAPI_ID);
        sched_param.sched_priority(sm, maxPriority);

        /*
         * Enforce that the user scheduler task is managed by sched_ext. The
         * task eagerly drains the list of enqueued tasks in its main work
         * loop, and then yields the CPU. The BPF scheduler only schedules the
         * user space scheduler task when at least one other task in the system
         * needs to be scheduled.
         */

        int err = sched_setscheduler(usersched_pid.get(), SCHED_EXT_UAPI_ID, sm);
        if (err != 0) {
            System.err.println("Failed to set scheduler for usersched task");
            System.exit(err);
        }

        // we might need to allocate in user space, but we're ignoring this here
    }

    /*
    static void bootstrap(char *comm)
{
	skel = SCX_OPS_OPEN(userland_ops, scx_userland);

	skel->rodata->num_possible_cpus = libbpf_num_possible_cpus();
	assert(skel->rodata->num_possible_cpus > 0);
	skel->rodata->usersched_pid = getpid();
	assert(skel->rodata->usersched_pid > 0);

	SCX_OPS_LOAD(skel, userland_ops, scx_userland, uei);

	enqueued_fd = bpf_map__fd(skel->maps.enqueued);
	dispatched_fd = bpf_map__fd(skel->maps.dispatched);
	assert(enqueued_fd > 0);
	assert(dispatched_fd > 0);

	SCX_BUG_ON(spawn_stats_thread(), "Failed to spawn stats thread");

	print_example_warning(basename(comm));
	ops_link = SCX_OPS_ATTACH(skel, userland_ops, scx_userland);
}
     */

    void startStatThread() {
        new Thread(this::runStatsLoop).start();
    }

    void bootstrap() {

        initTasks();
        set_scheduler();

        num_possible_cpus.set(Lib.libbpf_num_possible_cpus());
        if (num_possible_cpus.get() <= 0) {
            System.err.println("Failed to get number of possible CPUs");
            System.exit(-1);
        }
        usersched_pid.set(Lib_1.getpid());
        if (usersched_pid.get() <= 0) {
            System.err.println("Failed to get usersched pid");
            System.exit(-1);
        }

        // use bpf_map__attach_struct_ops to attach the ops
        var mapDescriptor = getMapDescriptorByName("userland_ops");
        if (mapDescriptor == null) {
            System.err.println("Failed to get map descriptor for userland_ops");
            System.exit(-1);
        }
        opsLink = bpf_map__attach_struct_ops(mapDescriptor.map());
        if (opsLink == null) {
            System.err.println("Failed to attach ops");
            System.exit(-1);
        }
    }

    void mainLoop() {
        while (!shouldStop.get()) {
            /*
             * Perform the following work in the main user space scheduler
             * loop:
             *
             * 1. Drain all tasks from the enqueued map, and enqueue them
             *    to the vruntime sorted list.
             *
             * 2. Dispatch a batch of tasks from the vruntime sorted list
             *    down to the kernel.
             *
             * 3. Yield the CPU back to the system. The BPF scheduler will
             *    reschedule the user space scheduler once another task has
             *    been enqueued to user space.
             */
            drain_enqueued_map();
            dispatch_batch();
            Thread.yield();
        }
    }

    @Override
    public void run() {
        set_scheduler();
        bootstrap();
        startStatThread();
        mainLoop();
        bpf_link__destroy(opsLink);
    }

    public static void main(String[] args) {
        try (var program = BPFProgram.load(SampleScheduler.class)) {
            new CommandLine(program).execute(args);
        }
    }

}
