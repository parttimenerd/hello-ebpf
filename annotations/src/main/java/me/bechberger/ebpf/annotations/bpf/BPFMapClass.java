package me.bechberger.ebpf.annotations.bpf;

import java.io.FileDescriptor;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Specify that a class is a BPF map class
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.CLASS)
public @interface BPFMapClass {
    /**
     * Template for the generated C code
     * <p>
     * Available placeholders:
     * <ul>
     *     <li>$field: The field name</li>
     *     <li>$maxEntries: max entries as specified in the {@link BPFMapDefinition} annotation</li>
     *     <li>$class: name of the class</li>
     *     <li>$c1, ...: C type names for every generic type parameter</li>
     *     <li>$b1, ...: BPFTypes</li>
     *     <li>$j1, ...: Java class names</li>
     * </ul>
     * <p>
     * Example:
     * {@snippet :
     *  struct {
     *     __uint (type, BPF_MAP_TYPE_RINGBUF);
     *     __uint (max_entries, $maxEntries);
     *  } $field SEC(".maps");
     * }
     */
    String cTemplate();

    /**
     * Code template for generating the Java generation code, see {@link BPFMapClass#cTemplate()} for available placeholders,
     * here are the additions:
     * <ul>
     *     <li>$fd: code that creates a FileDescriptor instance</li>
     * </ul>
     * <p>
     * Example:
     * {@snippet :
     * new $class<>($fd, $b1)
     * }
     */
    String javaTemplate();
}
