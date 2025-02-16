package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.runtime.TaskDefinitions;
import me.bechberger.ebpf.shared.TraceLog;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.helpers.BPFHelpers.bpf_strncmp;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SchedulerTimeoutTest {
    private static final String NO_SCHEDULE_NAME = "NO_SCHED";

    @BPF(license = "GPL")
    @Property(name = "sched_name", value = "timeout_test")
    @Property(name = "timeout_ms", value = "3000")
    public abstract static class ThreeSecondScheduler extends BPFProgram implements Scheduler {

        @Override
        public void enqueue(Ptr<TaskDefinitions.task_struct> p, long enq_flags) {
            if (bpf_strncmp(Ptr.of(p.val().comm).asString(), 16, NO_SCHEDULE_NAME) != 0) {
                @Unsigned int queueCount = scx_bpf_dsq_nr_queued(scx_dsq_id_flags.SCX_DSQ_GLOBAL.value());
                scx_bpf_dispatch(p, scx_dsq_id_flags.SCX_DSQ_GLOBAL.value(), 5_000_000 / queueCount, enq_flags);
            }
        }
    }

    @Test
    public void testThreeSecondTimeout() throws InterruptedException {
        try (var program = BPFProgram.load(ThreeSecondScheduler.class)) {
            var noScheduleThread = new Thread(() -> {
                while (true) {}
            });
            noScheduleThread.setName(NO_SCHEDULE_NAME);

            program.attachScheduler();
            noScheduleThread.start();

            Thread.sleep(2000);
            assertTrue(program.isSchedulerAttachedProperly());
            Thread.sleep(2000);
            assertFalse(program.isSchedulerAttachedProperly());

            TraceLog.getInstance().readAllAvailableLines(Duration.ofMillis(100));
        }
    }
}
