package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.QueuedTask;
import me.bechberger.ebpf.bpf.userspace.SchedulerHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The proof point: vtime ordering asserted offline, no kernel. */
class VtimeSampleTest {

    private QueuedTask task(int pid, long vtime, long weight) {
        var t = new QueuedTask(); t.pid = pid; t.vtime = vtime; t.weight = weight; return t;
    }

    @Test
    void lowestVtimeDispatchedFirst() {
        var sched = new VtimeSample();
        var harness = SchedulerHarness.forScheduler(sched).withCpus(8);

        harness.feed(task(3, 300, 100), task(1, 100, 100), task(2, 200, 100));
        harness.runBatch();

        List<Integer> order = harness.dispatches().stream().map(SchedulerHarness.Dispatch::pid).toList();
        assertEquals(List.of(1, 2, 3), order, "vtime policy dispatches lowest-vtime first");
    }
}
