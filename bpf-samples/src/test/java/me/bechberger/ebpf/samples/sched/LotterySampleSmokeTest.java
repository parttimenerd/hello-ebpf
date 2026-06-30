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
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();
        TestUtil.spawnCpuHogs(6, 5000);
        Thread.sleep(6000);
        sched.requestExit();
        runner.join(10_000);
        var s = sched.stats();
        assertTrue(s.dispatched() > 100, "dispatched too few: " + s);
        // Lottery duplicates may legitimately produce cancellations; allow up to 10%.
        assertTrue(s.dispatchFailed() < s.dispatched() / 10,
                "dispatch errors over 10%: " + s);
        assertTrue(s.ringDropped() < s.ringEnqueued() / 100, "ring dropped over 1%: " + s);
    }
}
