package me.bechberger.ebpf.bpf.userspace;

import me.bechberger.ebpf.bpf.QueuedTask;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TaskClassifierTest {

    enum Tier { INTERACTIVE, BATCH }

    private QueuedTask task(int pid, int prevCpu, long weight) {
        var t = new QueuedTask();
        t.pid = pid; t.prevCpu = prevCpu; t.weight = weight;
        return t;
    }

    private TaskClassifier<Tier> build() {
        return TaskClassifier.<Tier>builder()
            .classify(t -> t.weight >= 200 ? Tier.INTERACTIVE : Tier.BATCH)
            .policy(Tier.INTERACTIVE, t -> -1)                                  // ANY_CPU
            .policy(Tier.BATCH,       t -> t.prevCpu >= 0 ? t.prevCpu : -1)     // stick to prev cpu
            .build();
    }

    @Test
    void classifyRoutesToPerClassPolicy() {
        var c = build();
        assertEquals(-1, c.decide(task(1, 5, 300)));   // INTERACTIVE → ANY_CPU
        assertEquals(5,  c.decide(task(2, 5, 100)));   // BATCH, prevCpu=5 → 5
        assertEquals(-1, c.decide(task(3, -1, 100)));  // BATCH, no prevCpu → ANY_CPU
    }

    @Test
    void classOfExposesClassification() {
        var c = build();
        assertEquals(Tier.INTERACTIVE, c.classOf(task(1, 0, 500)));
        assertEquals(Tier.BATCH,       c.classOf(task(2, 0, 50)));
    }

    @Test
    void missingPolicyThrowsClearly() {
        var c = TaskClassifier.<Tier>builder()
            .classify(t -> Tier.INTERACTIVE)
            .policy(Tier.INTERACTIVE, t -> -1)
            .build();   // BATCH has no policy
        // classify always returns INTERACTIVE, so decide is fine; force a BATCH:
        var bad = TaskClassifier.<Tier>builder()
            .classify(t -> Tier.BATCH)
            .policy(Tier.INTERACTIVE, t -> -1)
            .build();
        assertThrows(IllegalStateException.class, () -> bad.decide(task(1, 0, 100)));
    }
}
