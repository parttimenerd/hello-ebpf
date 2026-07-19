// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;

import java.util.EnumMap;
import java.util.Map;
import java.util.function.Function;
import java.util.function.ToIntFunction;

/**
 * Maps a {@link QueuedTask} to a class enum, then to a per-class placement policy.
 * Turns the copy-paste "classify task → route to band" pattern into a table.
 *
 * <pre>{@code
 * var c = TaskClassifier.<Tier>builder()
 *     .classify(t -> tierOf(t))
 *     .policy(Tier.INTERACTIVE, t -> ANY_CPU)
 *     .policy(Tier.BATCH,       t -> t.prevCpu >= 0 ? t.prevCpu : ANY_CPU)
 *     .build();
 * // in a scheduler: protected int policy(QueuedTask t) { return c.decide(t); }
 * }</pre>
 */
public final class TaskClassifier<C extends Enum<C>> {

    private final Function<QueuedTask, C> classifier;
    private final Map<C, ToIntFunction<QueuedTask>> policies;

    private TaskClassifier(Function<QueuedTask, C> classifier, Map<C, ToIntFunction<QueuedTask>> policies) {
        this.classifier = classifier;
        this.policies = policies;
    }

    /** The class this task falls into. */
    public C classOf(QueuedTask t) { return classifier.apply(t); }

    /** Classify {@code t} and apply its class's placement policy; returns the target cpu (or ANY_CPU). */
    public int decide(QueuedTask t) {
        C c = classifier.apply(t);
        ToIntFunction<QueuedTask> p = policies.get(c);
        if (p == null) throw new IllegalStateException("no policy registered for class " + c);
        return p.applyAsInt(t);
    }

    public static <C extends Enum<C>> Builder<C> builder() { return new Builder<>(); }

    public static final class Builder<C extends Enum<C>> {
        private Function<QueuedTask, C> classifier;
        private final Map<C, ToIntFunction<QueuedTask>> policies = new java.util.HashMap<>();

        public Builder<C> classify(Function<QueuedTask, C> fn) { this.classifier = fn; return this; }

        public Builder<C> policy(C cls, ToIntFunction<QueuedTask> placement) {
            policies.put(cls, placement);
            return this;
        }

        public TaskClassifier<C> build() {
            if (classifier == null) throw new IllegalStateException("classify(...) is required");
            return new TaskClassifier<>(classifier, Map.copyOf(policies));
        }
    }
}
