package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.*;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.BPFArrayOfMaps;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.bpf.map.BPFHashOfMaps;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that the BTF {@code __array(values, innerTemplate)} idiom is emitted
 * in generated C for map-of-maps fields annotated with {@code @InnerMap}, and that
 * no {@code setInnerMapFd} runtime call appears (that was the old approach, removed
 * in favour of the BTF idiom which lets libbpf resolve the fd automatically at load time).
 */
public class InnerMapCTemplateTest {

    // ──────────────────────────────────────────────────────────────────────────
    // Test programs
    // ──────────────────────────────────────────────────────────────────────────

    @BPF(license = "GPL")
    public static abstract class HashOfMapsProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 512)
        BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

        @InnerMap("innerTemplate")
        @BPFMapDefinition(maxEntries = 256)
        BPFHashOfMaps<@Unsigned Integer, BPFHashMap<@Unsigned Long, @Unsigned Long>> perCpu;
    }

    @BPF(license = "GPL")
    public static abstract class ArrayOfMapsProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 64)
        BPFHashMap<@Unsigned Long, @Unsigned Long> innerTemplate;

        @InnerMap("innerTemplate")
        @BPFMapDefinition(maxEntries = 8)
        BPFArrayOfMaps<BPFHashMap<@Unsigned Long, @Unsigned Long>> slots;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Tests
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    public void hashOfMapsEmitsArrayAnnotation() {
        String code = BPFProgram.getCode(HashOfMapsProgram.class);
        assertTrue(code.contains("__array (values, innerTemplate)"),
                "Expected __array (values, innerTemplate) in generated C for HASH_OF_MAPS.\n"
                + "Generated code:\n" + code);
    }

    @Test
    public void hashOfMapsContainsBpfMapTypeHashOfMaps() {
        String code = BPFProgram.getCode(HashOfMapsProgram.class);
        assertTrue(code.contains("BPF_MAP_TYPE_HASH_OF_MAPS"),
                "Expected BPF_MAP_TYPE_HASH_OF_MAPS in generated C.\n"
                + "Generated code:\n" + code);
    }

    @Test
    public void arrayOfMapsEmitsArrayAnnotation() {
        String code = BPFProgram.getCode(ArrayOfMapsProgram.class);
        assertTrue(code.contains("__array (values, innerTemplate)"),
                "Expected __array (values, innerTemplate) in generated C for ARRAY_OF_MAPS.\n"
                + "Generated code:\n" + code);
    }

    @Test
    public void arrayOfMapsContainsBpfMapTypeArrayOfMaps() {
        String code = BPFProgram.getCode(ArrayOfMapsProgram.class);
        assertTrue(code.contains("BPF_MAP_TYPE_ARRAY_OF_MAPS"),
                "Expected BPF_MAP_TYPE_ARRAY_OF_MAPS in generated C.\n"
                + "Generated code:\n" + code);
    }

    @Test
    public void noSetInnerMapFdInGeneratedJava() {
        // The old approach injected a preLoad() call to setInnerMapFd().
        // With the BTF __array idiom, no runtime call is needed.
        // We verify via reflection that BPFProgram no longer has that method.
        boolean found = false;
        for (var m : BPFProgram.class.getDeclaredMethods()) {
            if ("setInnerMapFd".equals(m.getName())) {
                found = true;
                break;
            }
        }
        assertFalse(found,
                "BPFProgram.setInnerMapFd() must be absent after BTF __array migration");
    }
}
