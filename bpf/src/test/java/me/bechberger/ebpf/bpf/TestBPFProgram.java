package me.bechberger.ebpf.bpf;

import java.lang.annotation.*;

/**
 * Marks a test method as using a BPF program that should be loaded, optionally auto-attached,
 * and closed automatically via {@link BPFProgramExtension}.
 *
 * <p>Usage:
 * <pre>{@code
 * @ExtendWith(BPFProgramExtension.class)
 * class MyTest {
 *
 *     @BPF(license = "GPL")
 *     public static abstract class MyProg extends BPFProgram { ... }
 *
 *     @Test
 *     @TestBPFProgram(MyProg.class)
 *     void myTest(MyProg program) {
 *         // program is loaded and auto-attached
 *         TestUtil.triggerOpenAt();
 *         assertTrue(program.someVar.get());
 *     }
 * }
 * }</pre>
 *
 * @see BPFProgramExtension
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface TestBPFProgram {
    /** The BPF program class to load. */
    Class<? extends BPFProgram> value();

    /**
     * Whether to call {@link BPFProgram#autoAttachPrograms()} after loading.
     * Defaults to {@code true}.
     */
    boolean autoAttach() default true;
}
