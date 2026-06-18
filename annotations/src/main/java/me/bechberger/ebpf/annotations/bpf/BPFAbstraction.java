package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Marks a class as a pure compile-time abstraction over BPF C constructs.
 *
 * <p>An abstraction has <em>no runtime representation</em>:
 * <ul>
 *   <li>The annotation processor emits no C struct for the class.</li>
 *   <li>The compiler plugin emits no C local variable for abstraction-typed locals —
 *       they become aliases for the constructor's <em>carrier expression</em>.</li>
 *   <li>When an abstraction-typed field is declared on a {@code @BPF} program class,
 *       it is also inlined: no C struct member, reads substitute the carrier, and the
 *       constructor's C side-effect (if any) is prepended to the body of the BPF
 *       method named by {@link #constructorPrependTo} in source-declaration order.</li>
 *   <li>Every instance method call is template-rewritten inline by
 *       {@link BuiltinBPFFunction}.</li>
 * </ul>
 *
 * <h2>Annotation attributes</h2>
 * <dl>
 *   <dt>{@link #constructorPrependTo}</dt>
 *   <dd>Name of the {@code @BPFFunction}-annotated method on the enclosing {@code @BPF}
 *       class to whose generated C body the constructor's side-effect is prepended.
 *       Default: {@code "init"}.  Set to {@code ""} to disable lifting: the user must
 *       call the side-effecting constructor explicitly inside a {@code @BPFFunction},
 *       and the validator rejects side-effecting field initializers.</dd>
 * </dl>
 *
 * <h2>Authoring contract</h2>
 * <ol>
 *   <li>Every instance method: {@code @BuiltinBPFFunction} + {@code @NotUsableInJava} +
 *       throw {@link MethodIsBPFRelatedFunction}.</li>
 *   <li>Each constructor / static factory returning the abstraction declares the carrier
 *       via {@code @BuiltinBPFFunction(value="…sideEffect…", carrier="…expr…")}:
 *       <ul>
 *         <li>{@code value} — C statement emitted at the construction site / as lifted
 *             prologue.  Use {@code ""} for no side effect.</li>
 *         <li>{@code carrier} — C expression that {@code $this} resolves to at every
 *             subsequent call on the resulting variable or field.</li>
 *       </ul></li>
 *   <li>No instance fields on the abstraction class itself.
 *       {@code static final} constants are fine.</li>
 *   <li>Generic type parameters reach templates as {@code $C1}, {@code $C2}, …</li>
 * </ol>
 *
 * <h2>Forbidden usages — rejected with a clear diagnostic</h2>
 * <ul>
 *   <li>Side-effecting field initializer when {@code constructorPrependTo = ""}.</li>
 *   <li>Non-final abstraction-typed field on a {@code @BPF} class.</li>
 *   <li>{@code constructorPrependTo} names a method that doesn't exist or isn't
 *       {@code @BPFFunction}-annotated on the program class.</li>
 *   <li>Array element type ({@code MyAbs[]}).</li>
 *   <li>{@code Ptr<MyAbs>} or any {@code @BPFMapClass} generic argument.</li>
 *   <li>Instance method without {@code @BuiltinBPFFunction}.</li>
 *   <li>Instance field on the abstraction class itself.</li>
 * </ul>
 *
 * <h2>Carrier-expression cookbook</h2>
 *
 * <h3>Pattern 1 — id carrier with constructor side effect, lifted to init()</h3>
 * <pre>{@code
 * @BPFAbstraction(constructorPrependTo = "init")
 * public final class DispatchQueue {
 *     @BuiltinBPFFunction(value = "scx_bpf_create_dsq($arg1, -1)", carrier = "$arg1")
 *     @NotUsableInJava
 *     public DispatchQueue(@Unsigned long id) { throw new MethodIsBPFRelatedFunction(); }
 *
 *     @BuiltinBPFFunction("scx_bpf_dsq_move_to_local($this)")
 *     @NotUsableInJava
 *     public boolean moveToLocal() { throw new MethodIsBPFRelatedFunction(); }
 * }
 *
 * // In a @BPF class:
 * final DispatchQueue shared = new DispatchQueue(SHARED_DSQ);
 * // → no C field emitted
 * // → init() prologue (before user body):  scx_bpf_create_dsq(SHARED_DSQ, -1);
 * // → everywhere 'shared' appears:         SHARED_DSQ
 * shared.moveToLocal();  // → scx_bpf_dsq_move_to_local(SHARED_DSQ)
 * }</pre>
 *
 * <h3>Pattern 2 — static factory, no side effect (built-in DSQ or pointer)</h3>
 * <pre>{@code
 * @BuiltinBPFFunction(value = "", carrier = "SCX_DSQ_LOCAL")
 * @NotUsableInJava
 * public static DispatchQueue local() { throw new MethodIsBPFRelatedFunction(); }
 * }</pre>
 *
 * <h3>Pattern 3 — constructorPrependTo="" (explicit, no lifting)</h3>
 * <pre>{@code
 * @BPFAbstraction(constructorPrependTo = "")
 * public final class CpuMask {
 *     @BuiltinBPFFunction(value = "", carrier = "scx_bpf_get_idle_cpumask()")
 *     @NotUsableInJava
 *     public static CpuMask idle() { throw new MethodIsBPFRelatedFunction(); }
 *
 *     @BuiltinBPFFunction("bpf_cpumask_test_cpu($arg1, $this)")
 *     @NotUsableInJava
 *     public boolean test(int cpu) { throw new MethodIsBPFRelatedFunction(); }
 * }
 * // Inside @BPFFunction — must construct explicitly, no field initializer with side-effect allowed:
 * CpuMask idle = CpuMask.idle();  // carrier = scx_bpf_get_idle_cpumask()
 * idle.test(cpu);                 // → bpf_cpumask_test_cpu(cpu, scx_bpf_get_idle_cpumask())
 * idle.releaseIdle();
 * }</pre>
 *
 * <h3>Pattern 4 — scalar, no side effect</h3>
 * <pre>{@code
 * @BPFAbstraction(constructorPrependTo = "")
 * public final class EnqFlags {
 *     @BuiltinBPFFunction(value = "", carrier = "$arg1")
 *     @NotUsableInJava
 *     public static EnqFlags passThrough(long raw) { throw new MethodIsBPFRelatedFunction(); }
 *
 *     @BuiltinBPFFunction("($this | $arg1)")
 *     @NotUsableInJava
 *     public EnqFlags or(EnqFlags other) { throw new MethodIsBPFRelatedFunction(); }
 * }
 * }</pre>
 *
 * <h2>Template placeholder reference</h2>
 * <ul>
 *   <li>{@code $this} — receiver's carrier expression.</li>
 *   <li>{@code $arg1}, {@code $arg2}, … — call arguments (C-rendered).</li>
 *   <li>{@code $args} — all arguments, comma-separated.</li>
 *   <li>{@code $C1}, {@code $C2}, … — receiver class's type parameters.</li>
 *   <li>{@code $lambdaN:body} — body of the N-th lambda argument.</li>
 * </ul>
 *
 * <p>See {@code DispatchQueue}, {@code CpuMask}, {@code EnqFlags}, {@code KickFlags} for
 * concrete implementations.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface BPFAbstraction {

    /**
     * Name of the {@code @BPFFunction} method on the enclosing {@code @BPF} class
     * to whose generated C body constructor side-effects are prepended (in
     * source-declaration order of the fields) when this abstraction is used as a field.
     * Set to {@code ""} to require explicit construction inside a {@code @BPFFunction}.
     * Default: {@code "init"}.
     */
    String constructorPrependTo() default "init";
}
