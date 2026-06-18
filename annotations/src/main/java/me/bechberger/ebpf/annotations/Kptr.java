package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a struct field {@code Ptr<T>} as a BPF kernel pointer ({@code kptr}).
 *
 * <p>Emits the {@code __kptr} type qualifier on the C struct member so the
 * verifier and runtime track ownership and reference-counting correctly.
 * Typically used to store ownable kernel objects (such as {@code bpf_cpumask})
 * inside a map value, exchanged in/out via {@code bpf_kptr_xchg(&field, newPtr)}.
 *
 * <p>Example — a per-task allowed-CPU mask stored in task storage:
 * <pre>{@code
 *   @Type
 *   static class TaskCtx {
 *       @Kptr Ptr<bpf_cpumask> mask;
 *   }
 * }</pre>
 *
 * <p>Lowered to:
 * <pre>{@code
 *   struct TaskCtx {
 *     struct bpf_cpumask __kptr *mask;
 *   };
 * }</pre>
 *
 * <p>Use only on struct fields. The pointed-to type must be a kernel object
 * supported as a kptr (e.g. {@code bpf_cpumask}, {@code task_struct}).
 */
@Target({
        ElementType.FIELD,
        ElementType.TYPE_USE
})
@Retention(RetentionPolicy.SOURCE)
public @interface Kptr {
}
