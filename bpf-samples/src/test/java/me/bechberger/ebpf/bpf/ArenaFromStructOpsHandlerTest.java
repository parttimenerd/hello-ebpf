// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Framework-level integration test for the {@code ArenaAssociationPass} compiler-plugin pass.
 *
 * <p>Loads a scheduler ({@link ArenaFromStructOpsHandlerScheduler}) whose non-sleepable
 * {@code enqueue} struct_ops handler dereferences an {@link me.bechberger.ebpf.annotations.InArena
 * @InArena} {@code Ptr<Long>} backed by a {@link me.bechberger.ebpf.bpf.map.BPFArena}.
 *
 * <p>Without auto-injection of {@code bpf_arena_associate_arena()} at the top of the
 * {@code enqueue} body, the kernel verifier rejects the load with:
 * <pre>addr_space_cast insn can only be used in a program that has an associated arena</pre>
 *
 * <p>A regression that breaks the injection pass (e.g. fails to detect the
 * {@code BPF_STRUCT_OPS()} macro in {@code headerTemplate}, fails to compute transitive
 * arena reachability, or emits the helper but forgets to call it) shows up here even when
 * the unit tests still pass against the CAST shape.
 */
@ExtendWith(SchedulerExtension.class)
public class ArenaFromStructOpsHandlerTest {

    @Test
    @Timeout(15)
    @TestScheduler(ArenaFromStructOpsHandlerScheduler.class)
    void schedulerWithArenaDerefFromEnqueueAttaches(
            ArenaFromStructOpsHandlerScheduler sched) throws Exception {
        Thread.sleep(300);
        assertTrue(sched.isSchedulerAttachedProperly(),
                "Scheduler with @InArena deref in enqueue() must remain attached after 300 ms — "
                + "if the verifier rejected the load, the auto-injection pass is broken.");
        assertTrue(sched.readCounter() > 0,
                "enqueue() should have incremented the arena counter at least once in 300 ms; "
                + "got " + sched.readCounter() + ". Arena writes from the non-sleepable handler "
                + "are visible to Java via mmap'd userView, which proves the verifier accepted "
                + "the addr_space_cast lowering of *counter.");
    }
}
