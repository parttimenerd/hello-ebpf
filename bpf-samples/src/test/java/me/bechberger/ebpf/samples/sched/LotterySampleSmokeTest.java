// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.samples.sched;

import me.bechberger.ebpf.bpf.SchedulerExtension;
import me.bechberger.ebpf.bpf.TestUtil;
import me.bechberger.ebpf.bpf.userspace.Opts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SchedulerExtension.class)
public class LotterySampleSmokeTest {

    @Test
    @Timeout(30)
    void lotterySampleDispatchesUnderLoad() throws Exception {
        var sched = new LotterySample();
        Thread runner = new Thread(() -> {
            try {
                sched.runUntilExit(Opts.defaults());
            } catch (Throwable t) {
                System.err.println("[runner] threw: " + t);
                t.printStackTrace(System.err);
            }
        }, "lottery-runner");
        runner.setDaemon(true);
        runner.start();
        // Wait briefly for the scheduler to attach before generating load.
        Thread.sleep(500);
        System.err.println("[diag] after attach: " + sched.stats());
        TestUtil.spawnCpuHogs(3, 4000);
        System.err.println("[diag] after hogs:   " + sched.stats());
        Thread.sleep(5000);
        System.err.println("[diag] after sleep:  " + sched.stats());
        sched.requestExit();
        runner.join(10_000);
        var s = sched.stats();
        System.err.println("[diag] final:        " + s);
        assertTrue(s.dispatched() > 100, "dispatched too few: " + s);
        // Lottery duplicates may legitimately produce cancellations; allow up to 10%.
        assertTrue(s.dispatchFailed() < s.dispatched() / 10,
                "dispatch errors over 10%: " + s);
        assertTrue(s.ringDropped() < s.ringEnqueued() / 100, "ring dropped over 1%: " + s);
    }
}
