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
public class RustlandFifoSampleSmokeTest {

    @Test
    @Timeout(90)
    void fifoSampleDispatchesUnderLoad() throws Exception {
        var sched = new RustlandFifoSample();
        Thread runner = new Thread(() -> sched.runUntilExit(Opts.defaults()));
        runner.start();
        TestUtil.spawnCpuHogs(6, 5000);
        Thread.sleep(6000);
        sched.requestExit();
        runner.join(30_000);
        var s = sched.stats();
        assertTrue(s.dispatched() > 100,    "dispatched too few: " + s);
        assertTrue(s.dispatchFailed() < s.dispatched() / 100, "dispatch errors over 1%: " + s);
        assertTrue(s.ringDropped() < s.ringEnqueued() / 100, "ring dropped over 1%: " + s);
    }
}
