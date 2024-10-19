package me.bechberger.ebpf.annotations.bpf;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PropertyDefinitions {
    PropertyDefinition[] value();
}
