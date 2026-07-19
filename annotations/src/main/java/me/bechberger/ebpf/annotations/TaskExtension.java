package me.bechberger.ebpf.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a Java record as the per-task extension view for a {@code UserspaceScheduler}.
 *
 * <p>The record's components (in declaration order, natural alignment) describe how to
 * interpret the fixed {@code EXT_CAP}-byte extension tail appended to each
 * {@code QueuedTask}. The author fills the tail on the BPF side by overriding
 * {@code UserspaceSchedulerBase.fillExtension} and reads it back type-safely via
 * {@code QueuedTask.ext(MyExt.class)}.
 *
 * <p>v1 supports one extension record per scheduler. Retention is {@code SOURCE}:
 * the annotation is a documentation/marker aid only; the framework carries raw tail
 * bytes and the record view is a plain reader over them.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.SOURCE)
@Documented
public @interface TaskExtension {
}
