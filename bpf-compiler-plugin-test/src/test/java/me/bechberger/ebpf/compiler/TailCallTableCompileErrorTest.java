package me.bechberger.ebpf.compiler;

import me.bechberger.ebpf.annotations.bpf.BPFTailCallTable;
import me.bechberger.ebpf.annotations.bpf.TailCallSlot;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic sanity checks on the annotation shapes; the interesting compile-error
 * assertions arrive in Task 2 once the processor discovers them.
 */
public class TailCallTableCompileErrorTest {

    @Test
    public void tailCallTableTargetsField() {
        Target t = BPFTailCallTable.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.FIELD}, t.value());
    }

    @Test
    public void tailCallTableRuntimeRetained() {
        Retention r = BPFTailCallTable.class.getAnnotation(Retention.class);
        assertEquals(RetentionPolicy.RUNTIME, r.value());
    }

    @Test
    public void tailCallSlotTargetsMethod() {
        Target t = TailCallSlot.class.getAnnotation(Target.class);
        assertNotNull(t);
        assertArrayEquals(new ElementType[]{ElementType.METHOD}, t.value());
    }

    @Test
    public void tailCallSlotHasEmptyTableDefault() throws Exception {
        String def = (String) TailCallSlot.class
                .getMethod("table").getDefaultValue();
        assertEquals("", def);
    }
}
