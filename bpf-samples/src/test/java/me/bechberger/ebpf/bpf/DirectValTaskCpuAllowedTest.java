// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Framework-level integration test for {@link me.bechberger.ebpf.type.Ptr#directVal()}.
 *
 * <p>Loads a scheduler whose {@code enqueue} handler calls
 * {@code bpf_cpumask_test_cpu(0, p.directVal().cpus_ptr)}. The kernel
 * verifier accepts the load only when {@code directVal()} suppresses
 * CO-RE lifting on {@code cpus_ptr} — a regression that re-introduces
 * {@code BPF_CORE_READ} is rejected with a trusted-pointer error.
 */
@ExtendWith(SchedulerExtension.class)
public class DirectValTaskCpuAllowedTest {

    @Test
    @Timeout(15)
    @TestScheduler(DirectValTaskCpuAllowedScheduler.class)
    void schedulerAttachesWithTrustedCpumaskLoad(
            DirectValTaskCpuAllowedScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "Scheduler must remain attached after 300 ms — if the verifier "
                + "rejected the load, directVal() regressed to BPF_CORE_READ.");
    }
}
