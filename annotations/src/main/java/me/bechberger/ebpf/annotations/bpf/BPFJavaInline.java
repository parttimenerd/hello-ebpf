package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks an instance method whose body is written in Java and <em>inlined</em>
 * at every call site by the BPF compiler plugin.
 *
 * <p>Unlike {@link BuiltinBPFFunction}, which requires a hand-written C template string,
 * {@code @BPFJavaInline} lets you write the method body as ordinary Java:
 *
 * <pre>{@code
 * @BPFAbstraction(constructorPrependTo = "init")
 * public final class DispatchQueue {
 *     // The single carrier field: each occurrence of 'id' in method bodies
 *     // is replaced by the caller's carrier expression at compile time.
 *     @NotUsableInJava
 *     private final @Unsigned long id = 0;
 *
 *     @BPFJavaInline
 *     public void insert(Ptr<task_struct> p, long slice, EnqFlags flags) {
 *         scx_bpf_dsq_insert(p, id, slice, flags.value());
 *     }
 *
 *     @BPFJavaInline
 *     public boolean nonEmpty() {
 *         return nrQueued() > 0;   // nrQueued() is also @BPFJavaInline — inlined recursively
 *     }
 * }
 * }</pre>
 *
 * <h2>Carrier field substitution ({@code @BPFAbstraction} classes only)</h2>
 * When the declaring class is also annotated {@link BPFAbstraction}, all non-static instance
 * fields are treated as <em>carrier fields</em>. At each call site the compiler plugin
 * replaces every reference to a carrier field (by name) with the corresponding carrier
 * expression from the constructor or factory that created the abstraction instance.
 *
 * <p>On other (non-{@code @BPFAbstraction}) classes, instance fields keep their normal
 * {@code receiver->field} access pattern. Only {@code this} is rewritten — see below.
 *
 * <h2>{@code this} substitution (all classes)</h2>
 * Regardless of {@code @BPFAbstraction}, any occurrence of {@code this} inside a
 * {@code @BPFJavaInline} method body is replaced with the C expression for the
 * receiver at the call site. This allows plain classes to expose inline methods
 * whose bodies pass {@code this} to other helpers.
 *
 * <h2>No new C function emitted</h2>
 * The translated body is wrapped in a GNU statement expression
 * ({@code ({ ... })}) and substituted inline.  No top-level BPF C function is generated
 * for the method.
 *
 * <h2>Authoring contract</h2>
 * <ul>
 *   <li>The method body may call other {@code @BPFJavaInline} or {@code @BuiltinBPFFunction}
 *       methods — they are inlined recursively.</li>
 *   <li>Methods must be annotated with {@link NotUsableInJava} because they rely on BPF
 *       kfuncs that do not exist at Java runtime.</li>
 *   <li>Underlying BPF kfuncs should be exposed as {@code private static} methods annotated
 *       with {@link BuiltinBPFFunction} and {@link NotUsableInJava}.</li>
 * </ul>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFJavaInline {
}
