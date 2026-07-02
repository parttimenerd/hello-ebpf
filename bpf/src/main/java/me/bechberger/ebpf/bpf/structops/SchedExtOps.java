package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.StructOps;
import me.bechberger.ebpf.runtime.ScxDefinitions;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.runtime.runtime;
import me.bechberger.ebpf.type.Ptr;

/**
 * Marker interface for {@code sched_ext_ops}. Implement on a {@code @BPF}
 * class to write a sched-ext scheduler that does not extend
 * {@code SchedulerBase} — the plugin emits every overridden callback as a
 * {@code SEC("struct_ops/<field>")} program and attaches via
 * {@code bpf_map__attach_struct_ops}.
 *
 * <p>Every method has an empty default; users override only what they need.
 * The kernel requires at least {@code enqueue}, so failing to override
 * that is a load-time failure (surfaced as
 * {@code BPFLoadError.StructOpsAttachFailed}).
 *
 * <p>The existing {@link me.bechberger.ebpf.bpf.Scheduler} interface remains
 * for backwards compatibility with in-tree consumers; new schedulers may
 * use either. Sub-plan C consolidates them.
 */
@StructOps("sched_ext_ops")
public interface SchedExtOps {

    default int selectCpu(Ptr<TaskDefinitions.task_struct> p, int prevCpu, long wakeFlags) { return prevCpu; }
    default void enqueue(Ptr<TaskDefinitions.task_struct> p, long enqFlags) { }
    default void dispatch(int cpu, Ptr<TaskDefinitions.task_struct> prev) { }
    default void updateIdle(int cpu, boolean idle) { }
    default int  initTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_init_task_args> args) { return 0; }
    default int  init() { return 0; }
    default void exit(Ptr<ScxDefinitions.scx_exit_info> ei) { }
    default void runnable(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enqFlags) { }
    default void running(Ptr<TaskDefinitions.task_struct> p) { }
    default void enable(Ptr<TaskDefinitions.task_struct> p) { }
    default void disable(Ptr<TaskDefinitions.task_struct> p) { }
    default void stopping(Ptr<TaskDefinitions.task_struct> p, boolean runnable) { }
    default void dequeue(Ptr<TaskDefinitions.task_struct> p, @Unsigned long deqFlags) { }
    default void tick(Ptr<TaskDefinitions.task_struct> p) { }
    default void quiescent(Ptr<TaskDefinitions.task_struct> p, @Unsigned long enqFlags) { }
    default void cpuAcquire(int cpu, Ptr<ScxDefinitions.scx_cpu_acquire_args> args) { }
    default void cpuRelease(int cpu, Ptr<ScxDefinitions.scx_cpu_release_args> args) { }
    default void cpuOnline(int cpu) { }
    default void cpuOffline(int cpu) { }
    default boolean coreSchedBefore(Ptr<TaskDefinitions.task_struct> a, Ptr<TaskDefinitions.task_struct> b) { return false; }
    default boolean yield(Ptr<TaskDefinitions.task_struct> from, Ptr<TaskDefinitions.task_struct> to) { return false; }
    default void setWeight(Ptr<TaskDefinitions.task_struct> p, @Unsigned int weight) { }
    default void setCpumask(Ptr<TaskDefinitions.task_struct> p, Ptr<runtime.cpumask> cpumask) { }
    default void exitTask(Ptr<TaskDefinitions.task_struct> p, Ptr<ScxDefinitions.scx_exit_task_args> args) { }
    default void dump(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx) { }
    default void dumpCpu(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx, int cpu, boolean idle) { }
    default void dumpTask(Ptr<ScxDefinitions.scx_dump_ctx> dumpCtx, Ptr<TaskDefinitions.task_struct> p) { }
    default int  cgroupInit(Ptr<runtime.cgroup> cgrp, Ptr<ScxDefinitions.scx_cgroup_init_args> args) { return 0; }
    default void cgroupExit(Ptr<runtime.cgroup> cgrp) { }
    default int  cgroupPrepMove(Ptr<TaskDefinitions.task_struct> p, Ptr<runtime.cgroup> from, Ptr<runtime.cgroup> to) { return 0; }
    default void cgroupCancelMove(Ptr<TaskDefinitions.task_struct> p) { }
    default void cgroupMove(Ptr<TaskDefinitions.task_struct> p) { }
    default void cgroupSetWeight(Ptr<runtime.cgroup> cgrp, @Unsigned int weight) { }
    default void cgroupSetBandwidth(Ptr<runtime.cgroup> cgrp, @Unsigned long period, @Unsigned long quota, @Unsigned long burst) { }
    // "name" is a data field — String default; plugin lowers to char[16].
    default String name() { return "hello_ext"; }
}
