// SPDX-License-Identifier: GPL-2.0
/**
 * Write a Linux sched_ext scheduler in Java — policy in Java, transport in BPF.
 *
 * <p>You subclass {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler}, override one
 * or two hooks, and call {@link me.bechberger.ebpf.bpf.userspace.SchedulerRunner#run}. The
 * fixed BPF transport (enqueue → user ring → dispatch ring) is loaded for you; you never
 * touch it. Every scheduling decision flows through your Java class.
 *
 * <h2>The smallest scheduler</h2>
 * <pre>{@code
 * public final class RoundRobin extends UserspaceScheduler {
 *     protected int policy(QueuedTask t) { return ANY_CPU; }   // let BPF pick an idle CPU
 *     public static void main(String[] args) { SchedulerRunner.run(new RoundRobin(), args); }
 * }
 * }</pre>
 *
 * <h2>Which hook to override</h2>
 * <ul>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#policy(me.bechberger.ebpf.bpf.QueuedTask)
 *       policy(QueuedTask)} — one decision per task, in arrival order. Return the target CPU or
 *       {@code ANY_CPU}. Use this when each task can be placed on its own, with no reference to
 *       the other runnable tasks.</li>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#schedule(me.bechberger.ebpf.bpf.QueuedTask[], int)
 *       schedule(QueuedTask[], int)} — the whole batch at once. Override this when the dispatch
 *       <em>order</em> matters or tasks must be compared against each other: virtual-time
 *       fair-share, earliest-deadline-first, priority queues, work-stealing. Call
 *       {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#dispatchTask(me.bechberger.ebpf.bpf.QueuedTask, int)
 *       dispatchTask(t, cpu)} for each task you want to run. The default {@code schedule} just
 *       calls {@code policy} per task, so overriding one or the other is an either/or choice.</li>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#tick() tick()} — periodic
 *       housekeeping, called about once a second. Evict stale state, rebalance, log.</li>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#onSignal
 *       onSignal(Signal)} — react to a delivered kernel signal (Sub-project B).</li>
 * </ul>
 *
 * <h2>The dispatch contract</h2>
 * <p>Two rules cause most first-time surprises:
 * <ul>
 *   <li><b>Not dispatching drops the task.</b> Any task you receive in {@code schedule} but do
 *       not pass to {@code dispatchTask} is silently dropped; BPF re-enqueues it via a
 *       stall fallback after ~50&nbsp;ms. Dropping is a legitimate way to defer, but it is never
 *       free — a dropped task waits out that fallback delay.</li>
 *   <li><b>Retain a copy, never the flyweight.</b> The {@code QueuedTask[]} handed to
 *       {@code schedule} is a reused pool: entries are overwritten on the next batch. To keep a
 *       task past the current call (a priority queue, a deferral map) store
 *       {@link me.bechberger.ebpf.bpf.QueuedTask#copy() t.copy()}. A copy is fully dispatchable
 *       in a future batch.</li>
 * </ul>
 * <p>{@code dispatchTask} validates its CPU argument and fails fast (with a message pointing at
 * {@code ANY_CPU} / {@code copy()}) rather than letting the kernel reject a bad dispatch silently.
 *
 * <h2>Helpers — remove the boilerplate</h2>
 * <ul>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.DeferredQueue} — a cross-batch, copy-storing
 *       heap for sorted or time-gated policies. {@code deferOrdered(t, key)} for vtime/deadline
 *       order; {@code deferUntil(t, notBeforeNs)} for "not before time T"; drain the eligible
 *       front with {@code drainEligible(nowNs, max, sink)}.</li>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.TaskClassifier} — turns the "classify a task into
 *       a band, then route the band" pattern into a table:
 *       {@code builder().classify(fn).policy(BAND, placement).build()}. {@code classOf(t)} gives
 *       the band; {@code decide(t)} classifies and applies that band's placement in one call.</li>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.SchedulerRunner} — one-line {@code main}: wires
 *       the shutdown hook and the periodic {@code --stats-interval} printer, then calls
 *       {@code runUntilExit}.</li>
 * </ul>
 * <p>See {@code me.bechberger.ebpf.samples.sched.LatencyTierEdfSample} for the canonical shape
 * that combines a {@code TaskClassifier} (tier lookup) with a {@code DeferredQueue} (EDF order).
 *
 * <h2>Testing offline — no kernel required</h2>
 * <p>{@link me.bechberger.ebpf.bpf.userspace.SchedulerHarness} runs {@code schedule}/{@code tick}
 * against fabricated tasks in a plain JVM test and records what was dispatched:
 * <pre>{@code
 * var h = SchedulerHarness.forScheduler(new MyScheduler()).withCpus(8);
 * h.feed(task(1, 100), task(2, 50)).runBatch();
 * assertEquals(List.of(1, 2), h.dispatches().stream().map(Dispatch::pid).toList());
 * }</pre>
 * <p>For anything time-dependent (rate limiting, EDF deadlines, {@code deferUntil}) drive a
 * <b>virtual clock</b> so the test is deterministic and instant:
 * <pre>{@code
 * var h = SchedulerHarness.forScheduler(sched).withCpus(8).withVirtualClock(0);
 * h.feed(task(1, 100)).runBatch();          // dispatches at t=0
 * h.clear();
 * h.advanceMillis(5).feed().runBatch();     // now the gate has elapsed
 * }</pre>
 * The virtual clock replaces the scheduler's time source. This only works if your scheduler
 * reads time through {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#nanoTime()
 * nanoTime()} — <b>never call {@code System.nanoTime()} directly</b> in a scheduler you want to
 * test. ({@code .feed()} with no arguments runs an empty batch, which is how you advance time and
 * trigger {@code schedule} without new arrivals.)
 *
 * <h2>Observability</h2>
 * <ul>
 *   <li>{@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#stats() stats()} returns a
 *       {@link me.bechberger.ebpf.bpf.userspace.SchedStatsSnapshot} — ring/dispatch counters.
 *       A non-zero {@code dispatchFailed} means the kernel rejected dispatches.</li>
 *   <li>Per-class metrics: call {@code setClassMetrics(classifier)} once, then {@code perClass(band)}
 *       returns a {@link me.bechberger.ebpf.bpf.userspace.ClassMetrics} (count, p50, p99) per band.</li>
 *   <li>A bounded decision trace (dispatch/preempt/kick/drop) is available via
 *       {@code recentDecisions()} when {@code Opts.decisionTraceCapacity > 0}.</li>
 *   <li>Override {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#formatStats()
 *       formatStats()} to add a one-line custom summary the stats printer emits.</li>
 * </ul>
 *
 * <h2>Threading &amp; lifecycle</h2>
 * <p>{@code runUntilExit} blocks the calling thread and runs {@code policy}, {@code schedule},
 * and {@code tick} on it — none of them may block on external I/O. Call
 * {@link me.bechberger.ebpf.bpf.userspace.UserspaceScheduler#requestExit() requestExit()} from any
 * thread to stop at the next batch boundary.
 */
package me.bechberger.ebpf.bpf.userspace;
