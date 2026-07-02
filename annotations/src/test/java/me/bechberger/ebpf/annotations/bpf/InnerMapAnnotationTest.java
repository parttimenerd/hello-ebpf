package me.bechberger.ebpf.annotations.bpf;

import org.junit.jupiter.api.Test;
import java.lang.annotation.ElementType;
import java.lang.annotation.Target;
import static org.junit.jupiter.api.Assertions.*;

class InnerMapAnnotationTest {

    static class Fixture {
        @InnerMap("innerTemplate")
        Object outer;
    }

    @Test
    void annotationCarriesValueAndTargetsFieldOnly() throws Exception {
        var f = Fixture.class.getDeclaredField("outer");
        var ann = f.getAnnotation(InnerMap.class);
        assertNotNull(ann);
        assertEquals("innerTemplate", ann.value());

        Target t = InnerMap.class.getAnnotation(Target.class);
        assertArrayEquals(new ElementType[]{ElementType.FIELD}, t.value());
    }
}
