// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.InArena;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.map.BPFArena;
import me.bechberger.ebpf.bpf.sched.DispatchQueue;
import me.bechberger.ebpf.bpf.sched.EnqFlags;
import me.bechberger.ebpf.runtime.MmConstants;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.Ptr;

import static me.bechberger.ebpf.bpf.BPFJ.bpfArenaAllocPages;
import static me.bechberger.ebpf.runtime.ScxDefinitions.scx_bpf_create_dsq;

/**
 * Framework-level integration scheduler used by {@link ArenaFromStructOpsHandlerTest}.
 *
 * <p>Declares a {@link BPFArena} field plus an {@link InArena @InArena} {@code Ptr<Long>}
 * global initialized via {@code bpfArenaAllocPages} in {@code init()}, and dereferences
 * the pointer from the non-sleepable {@code enqueue} struct_ops entry handler.
 *
 * <p>This exercises the {@code ArenaAssociationPass} auto-injection: without the pass
 * prepending a {@code bpf_arena_associate_arena()} call at the top of the {@code enqueue}
 * handler, the kernel verifier would reject the {@code addr_space_cast} ({@code AS1 → AS0})
 * lowering of {@code *counter}.
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "arena_struct_ops_test")
@Property(name = "timeout_ms", value = "10000")
public abstract class ArenaFromStructOpsHandlerScheduler extends SchedulerBase implements Scheduler {

    @BPFMapDefinition(maxEntries = 1)
    BPFArena arena;

    /**
     * Counter written by the non-sleepable {@code enqueue} handler.
     * Initialized in {@link #init()} (sleepable) via {@code bpfArenaAllocPages}.
     */
    @InArena
    Ptr<Long> counter;

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public int init() {
        int rc = scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
        if (rc != 0) return rc;
        counter = bpfArenaAllocPages(arena, null, 1, MmConstants.NUMA_NO_NODE, 0);
        if (counter == null) {
            return -12;  // -ENOMEM
        }
        return 0;
    }

    /**
     * Non-sleepable struct_ops entry: dereferences the @InArena pointer.
     * The compiler plugin must auto-inject {@code bpf_arena_associate_arena()}
     * at the top of this body for the verifier to accept {@code *counter}.
     */
    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        counter.set(counter.val() + 1);
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        shared.moveToLocal();
    }

    public long readCounter() {
        return arena.userView().get(java.lang.foreign.ValueLayout.JAVA_LONG, 0);
    }
}
