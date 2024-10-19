package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Specifies a property that can be used throughout the generated C code of the program.
 * <p>
 * The property can be accessed in the C code by using {@code ${name}}.
 * <p>
 * Example:
 * {@snippet :
 * @PropertyDefinition(name = "sched_name", defaultValue = "scheduler")
 * public interface Scheduler {
 *     private static final String CODE = "char* name = "${name}";
 *    // ...
 * }
 *
 * @BPF
 * @Property(name = "sched_name", value = "scheduler")
 * public class Sched extends BPFProgram implements Scheduler {
 * }
 * }
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Repeatable(PropertyDefinitions.class)
public @interface PropertyDefinition {
    String name();
    String defaultValue();
    String regexp() default ".*";
}
