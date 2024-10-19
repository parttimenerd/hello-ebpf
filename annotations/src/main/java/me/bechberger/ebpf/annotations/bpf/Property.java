package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Sets the value of a property defined via {@link PropertyDefinition}.
 * <p>
 * Be aware that it has to confirm to the regular expression specified in the {@link PropertyDefinition#regexp()}.
 * <p>
 * Example:
 * {@snippet :
 * @Property(name = "sched_name", value = "scheduler")
 * public class Sched extends BPFProgram implements Scheduler {
 * }
 * }
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(Properties.class)
@Documented
public @interface Property {
    String name();
    String value();
}
