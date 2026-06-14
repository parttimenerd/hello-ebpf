package me.bechberger.ebpf.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Silences BPF compiler-plugin diagnostics by category for the annotated tree.
 *
 * <p>Categories are stable identifiers like {@code "region.user-deref"},
 * {@code "region.mixing"}, {@code "bounds.unguarded"}, {@code "helper.context"},
 * {@code "arena.escape"}, {@code "null.maybe"}. The special value {@code "all"}
 * suppresses every category in the annotated scope.
 *
 * <p>Suppression scope is the smallest enclosing tree carrying the annotation:
 * the {@code SuppressionScan} pass walks up from each diagnostic site to find
 * any enclosing suppression. Suppression is *total* — there is no "demote-to-warning"
 * mode. If a category is currently a warning and gets promoted to error in a future
 * release, an existing suppression continues to silence it.
 */
@Target({ElementType.METHOD, ElementType.LOCAL_VARIABLE, ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface SuppressBPFWarning {
    String[] value();
}
