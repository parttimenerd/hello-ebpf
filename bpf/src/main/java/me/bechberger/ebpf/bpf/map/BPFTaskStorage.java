package me.bechberger.ebpf.bpf.map;

import me.bechberger.ebpf.annotations.bpf.BPFMapClass;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.Ptr;

/**
 * BPF task-local storage map ({@code BPF_MAP_TYPE_TASK_STORAGE}) — a per-task
 * key-value store keyed implicitly by {@code task_struct *}.
 *
 * <p>Unlike a regular hash map keyed by PID, task-storage entries are managed
 * by the kernel and freed automatically when the task exits, eliminating
 * leaks and stale state.  Common uses: per-task latency accumulators,
 * per-task scheduler state, per-task tracing context.
 *
 * <p>Requires {@code BPF_F_NO_PREALLOC} (set in the cTemplate); the value type
 * {@code V} must be a {@code @Type} record/class so its size can be
 * computed at compile time.
 *
 * <p>BPF-side usage:
 * <pre>{@code
 *   @Type
 *   static class TaskCtx {
 *       long startTime;
 *       int wakeups;
 *   }
 *
 *   // task-storage ignores max_entries (kernel allocates per-task);
 *   // pass any positive value (the framework requires > 0)
 *   @BPFMapDefinition(maxEntries = 1)
 *   BPFTaskStorage<TaskCtx> taskCtx;
 *
 *   // get-or-create with zero-init
 *   Ptr<TaskCtx> ctx = taskCtx.bpf_getOrCreate(p);
 *   if (ctx != null) {
 *       ctx.val().wakeups++;
 *   }
 * }</pre>
 *
 * <p>Java-side access (from user-space) is intentionally not provided: task
 * storage is keyed by kernel-space {@code task_struct} pointers, which are
 * not stable identifiers from user space.
 */
@BPFMapClass(
        cTemplate = """
        struct {
            __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
            __uint(map_flags, BPF_F_NO_PREALLOC);
            __type(key, int);
            __type(value, $c1);
        } $field SEC(".maps");
        """,
        javaTemplate = """
        new $class<>($fd, $b1)
        """)
public class BPFTaskStorage<V> extends BPFMap {

    private final BPFType<V> valueType;

    public BPFTaskStorage(FileDescriptor fd, BPFType<V> valueType) {
        super(MapTypeId.TASK_STORAGE, fd);
        this.valueType = valueType;
    }

    public BPFType<V> getValueType() {
        return valueType;
    }

    /**
     * BPF-side: look up the storage entry for {@code task}, returning
     * {@code null} if no entry exists.
     *
     * <p>Lowers to {@code bpf_task_storage_get(&map, task, NULL, 0)}.
     *
     * @see me.bechberger.ebpf.runtime.helpers.BPFHelpers#bpf_task_storage_get(Ptr, Ptr, Ptr, long)
     */
    @BuiltinBPFFunction("bpf_task_storage_get(&$this, $arg1, NULL, 0)")
    @NotUsableInJava
    public Ptr<V> bpf_get(Ptr<task_struct> task) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: look up the storage entry for {@code task}, creating a
     * zero-initialized entry if none exists.
     *
     * <p>Lowers to {@code bpf_task_storage_get(&map, task, NULL,
     * BPF_LOCAL_STORAGE_GET_F_CREATE)}.  May return {@code null} on
     * allocation failure.
     */
    @BuiltinBPFFunction("bpf_task_storage_get(&$this, $arg1, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE)")
    @NotUsableInJava
    public Ptr<V> bpf_getOrCreate(Ptr<task_struct> task) {
        throw new MethodIsBPFRelatedFunction();
    }

    /**
     * BPF-side: delete the storage entry for {@code task}.
     *
     * <p>Lowers to {@code bpf_task_storage_delete(&map, task)}.  Returns
     * {@code 0} on success, {@code -ENOENT} if no entry existed.
     */
    @BuiltinBPFFunction("bpf_task_storage_delete(&$this, $arg1)")
    @NotUsableInJava
    public long bpf_delete(Ptr<task_struct> task) {
        throw new MethodIsBPFRelatedFunction();
    }
}
