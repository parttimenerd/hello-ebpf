package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an interface as the Java mirror of a kernel {@code bpf_struct_ops}
 * table. The interface's methods are the struct_ops callback slots; their
 * names lower to kernel field names via camelCase to snake_case.
 *
 * <p>When a {@code @BPF} class implements a {@code @StructOps}-annotated
 * interface, the hello-ebpf compiler plugin:
 * <ol>
 *   <li>Loads the BTF-derived layout for {@link #value()} from
 *       {@code bpf-compiler-plugin/src/main/resources/struct-ops-layouts/}.</li>
 *   <li>Validates each overridden method's return/arg types against the
 *       kernel field prototype.</li>
 *   <li>Emits one BPF program per overridden method plus a
 *       {@code SEC(".struct_ops.link")} struct instance for attach.</li>
 * </ol>
 *
 * <p>Un-overridden interface methods (defaults) emit nothing; the kernel
 * accepts NULL for optional callbacks. The interface itself must be
 * annotated directly — the plugin does not follow chains of extending
 * interfaces.
 *
 * <h2>Example: TCP congestion control</h2>
 * <pre>{@code
 * @StructOps("tcp_congestion_ops")
 * public interface TcpCongestionControl {
 *     default int ssthresh(Ptr<sock> sk) { return 4; }
 *     default void congAvoid(Ptr<sock> sk, int ack, int acked) {}
 * }
 *
 * @BPF
 * public abstract class MyCc extends BPFProgram implements TcpCongestionControl {
 *     @Override public int ssthresh(Ptr<sock> sk) { return 4; }
 *     @Override public void congAvoid(Ptr<sock> sk, int ack, int acked) {}
 * }
 *
 * try (var prog = BPFProgram.load(MyCc.class)) {
 *     // "myalgo" now appears in /proc/sys/net/ipv4/tcp_available_congestion_control
 * }
 * }</pre>
 *
 * <h2>Example: sched-ext</h2>
 * <pre>{@code
 * @StructOps(value = "sched_ext_ops",
 *            instanceName = "sched_ops",
 *            emittedNamePrefix = "sched_")
 * public interface Scheduler {
 *     @Sleepable default int init() { return 0; }
 *     default int enqueue(Ptr<task_struct> p, long enqFlags) { return 0; }
 * }
 *
 * @BPF(license = "GPL")
 * public abstract class MyScheduler extends SchedulerBase implements Scheduler {
 *     @Override
 *     public void enqueue(Ptr<task_struct> p, long enq_flags) {
 *         scx_bpf_dsq_insert(p, 0L, SCX_SLICE_DFL.value(), enq_flags);
 *     }
 * }
 * }</pre>
 * The plugin emits {@code SEC("struct_ops.s/sched_init")} for the {@code init}
 * slot (sleepable), {@code SEC("struct_ops/sched_enqueue")} for {@code enqueue}
 * (non-sleepable), and a single
 * {@code SEC(".struct_ops.link") struct sched_ext_ops sched_ops = { ... }}
 * initializer.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.TYPE)
@Documented
public @interface StructOps {

    /** Kernel BTF type name of the struct_ops kind, e.g.
     *  {@code "sched_ext_ops"}, {@code "tcp_congestion_ops"},
     *  {@code "Qdisc_ops"}, {@code "hid_bpf_ops"}. Must match a
     *  bundled layout file. */
    String value();

    /** BPF section prefix used for each callback's {@code SEC(...)}.
     *  Default {@code "struct_ops/"}. Set to {@code "struct_ops.s/"} for
     *  sleepable kinds. Rarely overridden per-interface; users typically
     *  don't touch it. */
    String sectionPrefix() default "struct_ops/";

    /** Optional override for the C-side struct instance variable name.
     *  Defaults to the implementing {@code @BPF} class's simple name.
     *  Used for the {@code SEC(".struct_ops.link") struct <kind> <name>}
     *  declaration and matches libbpf's map-name lookup. */
    String instanceName() default "";

    /** Prefix prepended to each emitted BPF function name and to the corresponding
     *  {@code .field = (void *)<name>} initializer entry. Default empty.
     *
     *  <p>Set to {@code "sched_"} on the sched-ext {@code Scheduler} interface so
     *  emitted symbols match the pre-@StructOps scheduler C exactly. The kernel
     *  doesn't care about emitted C function names — only the field pointers in
     *  the struct instance matter for attach — but preserving symbol names avoids
     *  a spurious diff in trace_pipe output and in generated {@code .c} files
     *  consumers may have inspected. */
    String emittedNamePrefix() default "";
}
