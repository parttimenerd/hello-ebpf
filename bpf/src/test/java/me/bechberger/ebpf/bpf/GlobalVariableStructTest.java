package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Kprobe;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.runtime.PtDefinitions;
import me.bechberger.ebpf.type.Ptr;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests {@link GlobalVariable} with struct ({@link Type}-annotated record) types,
 * verifying that:
 * <ul>
 *   <li>A struct global variable written from Java is readable from BPF.</li>
 *   <li>A struct global variable written from BPF is readable from Java.</li>
 *   <li>Nested struct global variables work correctly.</li>
 * </ul>
 */
public class GlobalVariableStructTest {

    // ----- 1. Java→BPF round-trip -----

    @BPF(license = "GPL")
    public static abstract class JavaToBpfProgram extends BPFProgram {

        @Type
        record Point(int x, int y) {}

        /** Written from Java; read from BPF. */
        final GlobalVariable<Point> input = new GlobalVariable<>(new Point(0, 0));

        /** Written from BPF; read from Java. */
        final GlobalVariable<Integer> sumXY = new GlobalVariable<>(0);

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            sumXY.set(input.get().x() + input.get().y());
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testStructGlobalJavaToBpf() throws InterruptedException {
        try (var program = BPFProgram.load(JavaToBpfProgram.class)) {
            program.input.set(new JavaToBpfProgram.Point(3, 7));
            assertEquals(new JavaToBpfProgram.Point(3, 7), program.input.get(),
                    "Java-written struct should be readable via Java get()");

            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            assertEquals(10, program.sumXY.get().intValue(),
                    "BPF should compute 3 + 7 = 10 from struct fields");
        }
    }

    // ----- 2. BPF→Java round-trip -----

    @BPF(license = "GPL")
    public static abstract class BpfToJavaProgram extends BPFProgram {

        @Type
        record Stats(int value, int doubled) {}

        /** BPF writes statistics into this struct global. */
        final GlobalVariable<Stats> stats = new GlobalVariable<>(new Stats(0, 0));

        final GlobalVariable<Integer> input = new GlobalVariable<>(42);

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);
            int v = input.get();
            Ptr<Stats> sp = Ptr.of(stats.get());
            Ptr.of(sp.val().value()).set(v);
            Ptr.of(sp.val().doubled()).set(v * 2);
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testStructGlobalBpfToJava() throws InterruptedException {
        try (var program = BPFProgram.load(BpfToJavaProgram.class)) {
            program.input.set(7);

            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            var stats = program.stats.get();
            assertNotNull(stats, "stats struct should not be null");
            assertEquals(7, stats.value(), "value should be 7");
            assertEquals(14, stats.doubled(), "doubled should be 14");
        }
    }

    // ----- 3. Nested struct global variables -----

    @BPF(license = "GPL")
    public static abstract class NestedStructProgram extends BPFProgram {

        @Type
        record Dimensions(int width, int height) {}

        @BPFMapDefinition(maxEntries = 2)
        BPFArray<Integer> results;

        final GlobalVariable<Dimensions> dims = new GlobalVariable<>(new Dimensions(0, 0));

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            // Read width and height from the global struct and write area/perimeter.
            int w = dims.get().width();
            int h = dims.get().height();
            results.put(0, w * h);       // area
            results.put(1, 2 * (w + h)); // perimeter
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testStructGlobalFieldRead() throws InterruptedException {
        try (var program = BPFProgram.load(NestedStructProgram.class)) {
            program.dims.set(new NestedStructProgram.Dimensions(6, 4));

            // Verify Java-side get() reflects the written value.
            var rb = program.dims.get();
            assertEquals(6, rb.width(),  "width should be 6 after Java set");
            assertEquals(4, rb.height(), "height should be 4 after Java set");

            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");

            assertEquals(24, program.results.get(0).intValue(), "area = 6*4 = 24");
            assertEquals(20, program.results.get(1).intValue(), "perimeter = 2*(6+4) = 20");
        }
    }
}
