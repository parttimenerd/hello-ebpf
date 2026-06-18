package me.bechberger.ebpf.bpf;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bundle of cooperating {@link BPFProgram} instances that share pinned maps via
 * {@code @SharedFrom}.
 *
 * <p>Members are added in dependency order — producers first, then consumers.
 * {@link #close()} closes them in reverse order, so {@code BPFProgram.close()}'s
 * dependent-tracking guard never trips on group-managed programs.
 *
 * <p>Typical use:
 * <pre>{@code
 * try (var grp = BPFProgramGroup.of(uprobes, sched)
 *         .andAttach(uprobes::autoAttachPrograms)
 *         .andAttach(sched::attachScheduler)) {
 *     grp.runUntilInterrupted();
 * }
 * }</pre>
 */
public final class BPFProgramGroup implements AutoCloseable {

    /** Runnable that may throw a checked exception. */
    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    private final List<BPFProgram> members;

    private BPFProgramGroup(List<BPFProgram> members) {
        this.members = members;
    }

    /**
     * Build a group from one or more programs, listed in load/dependency order
     * (producers first, consumers last). The first program is required because
     * a zero-program group has no useful semantics.
     */
    public static BPFProgramGroup of(BPFProgram first, BPFProgram... rest) {
        if (first == null) throw new IllegalArgumentException("first program must not be null");
        var list = new ArrayList<BPFProgram>(1 + rest.length);
        list.add(first);
        for (var p : rest) {
            if (p == null) throw new IllegalArgumentException("program must not be null");
            list.add(p);
        }
        return new BPFProgramGroup(list);
    }

    /** Members in load order (producers first). */
    public List<BPFProgram> members() {
        return Collections.unmodifiableList(members);
    }

    /**
     * Run an attach step. Wraps checked exceptions as {@link RuntimeException}
     * so chained calls stay terse.
     */
    public BPFProgramGroup andAttach(ThrowingRunnable attachStep) {
        try {
            attachStep.run();
        } catch (RuntimeException re) {
            throw re;
        } catch (Exception e) {
            throw new RuntimeException("attach step failed", e);
        }
        return this;
    }

    /**
     * Drain ring buffers across all members until SIGINT or {@code timeout} elapses.
     * Mirrors {@link BPFProgram#runUntilInterrupted(Duration, Duration)} but polls
     * every member each tick so a producer's ring buffer doesn't starve while a
     * consumer is being polled.
     */
    public void runUntilInterrupted(Duration timeout, Duration pollInterval) {
        if (pollInterval == null) pollInterval = Duration.ofMillis(100);
        final long deadlineNanos = (timeout == null || timeout.isNegative() || timeout.isZero())
                ? Long.MAX_VALUE
                : System.nanoTime() + timeout.toNanos();

        AtomicBoolean interrupted = new AtomicBoolean(false);
        Thread shutdownHook = new Thread(() -> interrupted.set(true));
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        try {
            final long sleepMs = pollInterval.toMillis();
            while (!interrupted.get() && System.nanoTime() < deadlineNanos) {
                for (var p : members) p.consumeAndThrow();
                try {
                    Thread.sleep(sleepMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } finally {
            try { Runtime.getRuntime().removeShutdownHook(shutdownHook); } catch (IllegalStateException ignored) {}
            for (var p : members) p.consumeAndThrow();
        }
    }

    /** {@link #runUntilInterrupted(Duration, Duration)} with no wall-clock limit. */
    public void runUntilInterrupted() {
        runUntilInterrupted(Duration.ZERO, null);
    }

    /**
     * Close members in reverse dependency order (consumers before producers).
     * Failures are collected and rethrown as a single exception so a flaky
     * consumer close doesn't strand a producer.
     */
    @Override
    public void close() {
        List<Throwable> failures = new ArrayList<>();
        for (int i = members.size() - 1; i >= 0; i--) {
            try {
                members.get(i).close();
            } catch (Throwable t) {
                failures.add(t);
            }
        }
        if (!failures.isEmpty()) {
            RuntimeException re = new RuntimeException(
                    "BPFProgramGroup.close failed for " + failures.size() + " member(s)",
                    failures.get(0));
            for (int i = 1; i < failures.size(); i++) re.addSuppressed(failures.get(i));
            throw re;
        }
    }

    @Override
    public String toString() {
        return "BPFProgramGroup" + Arrays.toString(
                members.stream().map(p -> p.getClass().getSimpleName()).toArray());
    }
}
