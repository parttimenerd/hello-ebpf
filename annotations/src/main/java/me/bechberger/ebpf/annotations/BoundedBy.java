package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares a static upper bound on the number of iterations of a {@code for} loop that uses the
 * annotated variable as its index.
 *
 * <p>The BPF verifier rejects loops whose bound is a runtime value (E2BIG / loop-complexity
 * limit). The compiler plugin uses {@code @BoundedBy(N)} to rewrite
 * <pre>
 *   for (&#64;BoundedBy(64) int cpu = 0; cpu &lt; ncpus; cpu++) { ... }
 * </pre>
 * into the verifier-friendly form
 * <pre>
 *   for (int cpu = 0; cpu &lt; 64; cpu++) {
 *       if (!(cpu &lt; ncpus)) break;
 *       ...
 *   }
 * </pre>
 *
 * <p>{@code N} must be a compile-time constant.
 */
@Target({ElementType.LOCAL_VARIABLE, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface BoundedBy {
    /** Static upper bound on the iteration count of the loop. */
    int value();
}
