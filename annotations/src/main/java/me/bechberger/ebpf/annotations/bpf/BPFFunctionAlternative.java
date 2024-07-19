package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

/**
 * Annotate a method that cannot be used in BPF, but for which there
 * is an alternative method that can.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.CLASS)
@Documented
public @interface BPFFunctionAlternative {

    /**
     * The name of the alternative method
     */
    String value();
}
