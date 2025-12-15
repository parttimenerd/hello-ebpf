// SPDX-License-Identifier: GPL-2.0
// Based on:
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_simple.h
// https://github.com/sched-ext/scx/blob/63a2eecce801b74c27bf2a64d62b001f293ee7d2/scheds/c/scx_simple.bpf.c

/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 * Copyright (c) 2024 Johannes Bechberger
 */

package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.annotations.AlwaysInline;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import me.bechberger.ebpf.type.Ptr;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_dsq_id_flags.SCX_DSQ_LOCAL;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_public_consts.SCX_SLICE_DFL;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_get_smp_processor_id;
import static picocli.CommandLine.Option;

@BPF(license = "GPL")
@Property(name = "sched_name", value = "sample_scheduler")
public abstract class SampleScheduler extends BPFProgram implements Scheduler, Runnable {


    final GlobalVariable<Boolean> fifo_sched = new GlobalVariable<>(false);

    final GlobalVariable<@Unsigned Long> vtime_now = new GlobalVariable<>(0L);

    /*
     * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
     * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
     * therefore create a separate DSQ with ID 0 that we dispatch to and consume
     * from. If scx_simple only supported global FIFO scheduling, then we could
     * just use SCX_DSQ_GLOBAL.
     */
    static final long SHARED_DSQ_ID = 0;

    @Type
    static class Stats {
        long global;
        long local;
    }

    @BPFMapDefinition(maxEntries = 100)
    BPFHashMap<Integer, Stats> statsPerCPU;

    @BPFMapDefinition(maxEntries = 100000)
    BPFLRUHashMap<@Unsigned Integer, @Unsigned Long> enqueuesPerProcess;

    @BPFFunction
    void incrementStats(boolean local) {
        int processor = bpf_get_smp_processor_id();
        Ptr<Stats> statsPtr = statsPerCPU.bpf_get(processor);
        if (statsPtr == null) {
            var nee = new Stats();
            if (local) {
                nee.local = 1;
                nee.global = 0;
            } else {
                nee.global = 1;
                nee.local = 0;
            }
            statsPerCPU.put(processor, nee);
        } else {
            if (local) {
                statsPtr.val().local++;
            } else {
                statsPtr.val().global++;
            }
        }
    }

    @BPFFunction
    @AlwaysInline
    boolean isSmaller(@Unsigned long a, @Unsigned long b) {
        return (long)(a - b) < 0;
    }

    @Override
    public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
        boolean is_idle = false;
        int cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, Ptr.of(is_idle));
        if (is_idle) {
            incrementStats(true);
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL.value(), SCX_SLICE_DFL.value(),0);
        }
        return cpu;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        incrementStats(false);
        if (fifo_sched.get()) {
            scx_bpf_dsq_insert(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), enq_flags);
        } else {

            @Unsigned long vtime = p.val().scx.dsq_vtime;

            /*
             * Limit the amount of budget that an idling task can accumulate
             * to one slice.
             */
            if (isSmaller(vtime, vtime_now.get() - SCX_SLICE_DFL.value())) {
                vtime = vtime_now.get() - SCX_SLICE_DFL.value();
            } else {
                recordEnqueue(p);
            }
            scx_bpf_dsq_insert_vtime(p, SHARED_DSQ_ID, SCX_SLICE_DFL.value(), vtime, enq_flags);
        }
    }

    @BPFFunction
    void recordEnqueue(Ptr<task_struct> p) {
        var pid = p.val().pid;
        var res = enqueuesPerProcess.bpf_get(pid);
        if (res != null) {
            res.set(res.val() + 1);
        } else {
            var one = 1L;
            enqueuesPerProcess.put(pid, one);
        }
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
    }

    @Override
    public void running(Ptr<task_struct> p) {
        if (fifo_sched.get()) {
            return;
        }
        /*
         * Global vtime always progresses forward as tasks start executing. The
         * test and update can be performed concurrently from multiple CPUs and
         * thus racy. Any error should be contained and temporary. Let's just
         * live with it.
         */
        @Unsigned long vtime = p.val().scx.dsq_vtime;
        if (isSmaller(vtime_now.get(), vtime)) {
            vtime_now.set(vtime);
        }
    }

    @Override
    public void stopping(Ptr<task_struct> p, boolean runnable) {
        if (fifo_sched.get()) {
            return;
        }
        /*
         * Scale the execution time by the inverse of the weight and charge.
         *
         * Note that the default yield implementation yields by setting
         * @p->scx.slice to zero and the following would treat the yielding task
         * as if it has consumed all its slice. If this penalizes yielding tasks
         * too much, determine the execution time by taking explicit timestamps
         * instead of depending on @p->scx.slice.
         */
        p.val().scx.dsq_vtime += (SCX_SLICE_DFL.value() - p.val().scx.slice) * 100 / p.val().scx.weight;
    }

    @Override
    public void enable(Ptr<task_struct> p) {
        p.val().scx.dsq_vtime = vtime_now.get();
    }

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @Option(names = "--verbose")
    boolean verbose = false;

    @Option(names = "--fifo")
    boolean fifoOpt = false;

    void printDispatchStats() {
        List<List<Long>> statsRows = new ArrayList<>();
        statsRows.add(new ArrayList<>());
        statsRows.add(new ArrayList<>());
        statsRows.add(new ArrayList<>());
        statsPerCPU.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEach((e) -> {
            var cpu = e.getKey();
            var stats = e.getValue();
            statsRows.get(0).add((long)cpu);
            statsRows.get(1).add(stats.local);
            statsRows.get(2).add(stats.global);
        });

        Function<Long, String> format = (Long l) -> String.format("%-9d", l);
        Function<List<Long>, String> formatRow = (List<Long> row) -> String.join(" ", row.stream().map(format).toList());
        // header: | cpu id | ...
        System.out.println("      " + String.join(" ", formatRow.apply(statsRows.get(0))));
        // header: | local  | ...
        System.out.println("local " + String.join(" ", formatRow.apply(statsRows.get(1))));
        // header: | global | ...
        System.out.println("global " + String.join(" ", formatRow.apply(statsRows.get(2))));
    }

    String getProcessName(int pid) {
        try {
            return Files.readString(Paths.get("/proc/" + pid + "/comm")).trim();
        } catch (Exception e) {
            return "unknown";
        }
    }

    void printVTimeStats() {
        var top5 = enqueuesPerProcess.entrySet().stream()
                .sorted(Comparator.comparingLong(e -> -e.getValue()))
                .limit(10)
                .toList();
        // Print table header
        System.out.printf("%-10s %-20s %-10s%n", "PID", "Process Name", "Enqueue Count");
        System.out.println("---------------------------------------------");

        // Print each process in the top 5
        for (var e : top5) {
            var pid = e.getKey();
            var count = e.getValue();
            var name = getProcessName(pid); // Assuming getProcessName(pid) retrieves the process name by PID
            name = name.substring(0, Math.min(20, name.length())); // Truncate the process name to 20 characters
            System.out.printf("%-10d %-20s %10d%n", pid, name, count);
        }
    }

    void printStats() {
        printDispatchStats();
        printVTimeStats();
    }

    void statsLoop() {
       try {
            while (true) {
                System.out.println("Stats:");
                Thread.sleep(1000);
                printStats();
            }
       } catch (InterruptedException e) {
       }
    }

    @Override
    public void run() {
        fifo_sched.set(fifoOpt);
        attachScheduler();
        if (verbose) {
            statsLoop();
        } else {
            try {
                Thread.currentThread().join();
            } catch (InterruptedException e) {
            }
        }
    }

    public static void main(String[] args) {
        try (var program = BPFProgram.load(SampleScheduler.class)) {
            new CommandLine(program).execute(args);
        }
    }

}
