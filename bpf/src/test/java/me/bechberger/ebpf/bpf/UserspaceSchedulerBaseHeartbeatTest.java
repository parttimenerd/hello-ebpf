package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;

import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_dsq_move_to_local;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Compile-side smoke test for Task 7: heartbeat {@code bpf_timer} + fork tracepoint.
 *
 * <p>Exercises the compiler plugin via {@link BPFProgram#getCode} on the
 * {@link UserspaceSchedulerBase} class itself (which carries {@code @BPF(license="GPL")}),
 * avoiding the need to instantiate a concrete subclass whose C compilation can
 * hit the pre-existing struct-ordering issue in the base class.
 *
 * <p>Asserts the generated C contains the expected tokens for:
 * <ul>
 *   <li>{@code bpf_timer_init} — timer initialization in {@code initHeartbeat}</li>
 *   <li>{@code bpf_timer_set_callback} — method-reference lowering</li>
 *   <li>{@code bpf_timer_start} — timer arming / re-arming</li>
 *   <li>{@code tp/sched/sched_process_fork} — tracepoint section</li>
 *   <li>{@code bpf_map_update_elem} — from {@code frameworkPids.bpf_put}</li>
 *   <li>{@code scx_bpf_kick_cpu} — from {@code DispatchQueue.kickCpu} in tick</li>
 * </ul>
 */
public class UserspaceSchedulerBaseHeartbeatTest {

    @Test
    public void testHeartbeatTimerInitEmitted() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("bpf_timer_init"),
                "expected bpf_timer_init call in initHeartbeat in generated C:\n" + code);
    }

    @Test
    public void testHeartbeatTimerSetCallbackEmitted() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("bpf_timer_set_callback"),
                "expected bpf_timer_set_callback (method-ref lowering) in generated C:\n" + code);
    }

    @Test
    public void testHeartbeatTimerStartEmitted() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("bpf_timer_start"),
                "expected bpf_timer_start call in generated C:\n" + code);
    }

    @Test
    public void testForkTracepointSectionEmitted() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("tp/sched/sched_process_fork"),
                "expected tp/sched/sched_process_fork in generated C:\n" + code);
    }

    @Test
    public void testForkTracepointUpdatesFrameworkPids() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("bpf_map_update_elem"),
                "expected bpf_map_update_elem (from frameworkPids.bpf_put) in generated C:\n" + code);
    }

    @Test
    public void testHeartbeatTickKicksCpu() {
        String code = BPFProgram.getCode(UserspaceSchedulerBase.class);
        assertTrue(code.contains("scx_bpf_kick_cpu"),
                "expected scx_bpf_kick_cpu (from DispatchQueue.kickCpu) in generated C:\n" + code);
    }
}
