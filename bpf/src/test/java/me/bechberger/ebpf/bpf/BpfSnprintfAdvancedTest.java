package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Size;
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
 * Tests {@link BPFJ#bpf_snprintf} with various format specifiers:
 * <ul>
 *   <li>{@code %d} — signed decimal integer</li>
 *   <li>{@code %u} — unsigned decimal integer</li>
 *   <li>{@code %x} — lowercase hex</li>
 *   <li>{@code %ld} — signed long</li>
 * </ul>
 *
 * <p>Each test formats a specific string, then stores character codes into a
 * {@link BPFArray} so user-space can verify the exact formatted output.
 */
public class BpfSnprintfAdvancedTest {

    // --- Helpers ---

    /** Formats {@code format} string with the given expected result into a char code array. */
    private static void assertFormattedChars(BPFArray<Integer> chars, String expected) {
        for (int i = 0; i < expected.length(); i++) {
            int got = chars.get(i);
            assertEquals((int) expected.charAt(i), got,
                    "char[" + i + "] should be '" + expected.charAt(i) +
                    "' (" + (int) expected.charAt(i) + "), got " + got + " ('" + (char) got + "')");
        }
    }

    // --- Program 1: unsigned decimal ---

    @BPF(license = "GPL")
    public static abstract class UnsignedProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFArray<Integer> chars;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) String out = "";
            BPFJ.bpf_snprintf(out, "u=%u", 42);

            // "u=42" → 4 chars
            for (int i = 0; i < 4; i++) {
                chars.put(i, (int) out.charAt(i));
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testSnprintfUnsigned() throws InterruptedException {
        try (var program = BPFProgram.load(UnsignedProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            assertFormattedChars(program.chars, "u=42");
        }
    }

    // --- Program 2: hex format ---

    @BPF(license = "GPL")
    public static abstract class HexProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFArray<Integer> chars;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) String out = "";
            BPFJ.bpf_snprintf(out, "0x%x", 255);

            // "0xff" → 4 chars
            for (int i = 0; i < 4; i++) {
                chars.put(i, (int) out.charAt(i));
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testSnprintfHex() throws InterruptedException {
        try (var program = BPFProgram.load(HexProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            assertFormattedChars(program.chars, "0xff");
        }
    }

    // --- Program 3: negative decimal ---

    @BPF(license = "GPL")
    public static abstract class NegativeProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFArray<Integer> chars;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) String out = "";
            BPFJ.bpf_snprintf(out, "%d", -7);

            // "-7" → 2 chars
            for (int i = 0; i < 2; i++) {
                chars.put(i, (int) out.charAt(i));
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testSnprintfNegative() throws InterruptedException {
        try (var program = BPFProgram.load(NegativeProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            assertFormattedChars(program.chars, "-7");
        }
    }

    // --- Program 4: multiple args ---

    @BPF(license = "GPL")
    public static abstract class MultiArgProgram extends BPFProgram {

        @BPFMapDefinition(maxEntries = 16)
        BPFArray<Integer> chars;

        final GlobalVariable<Boolean> done = new GlobalVariable<>(false);

        @Kprobe("do_sys_openat2")
        int onOpen(Ptr<PtDefinitions.pt_regs> ctx) {
            if (done.get()) return 0;
            done.set(true);

            @Size(16) String out = "";
            // "%d+%d=%d" with 3, 4, 7 → "3+4=7" (5 chars)
            BPFJ.bpf_snprintf(out, "%d+%d=%d", 3, 4, 7);

            for (int i = 0; i < 5; i++) {
                chars.put(i, (int) out.charAt(i));
            }
            return 0;
        }
    }

    @Test
    @Timeout(10)
    public void testSnprintfMultipleArgs() throws InterruptedException {
        try (var program = BPFProgram.load(MultiArgProgram.class)) {
            program.autoAttachPrograms();
            TestUtil.triggerOpenAt();

            long deadline = System.currentTimeMillis() + 5000;
            while (!program.done.get() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(program.done.get(), "kprobe should have fired");
            assertFormattedChars(program.chars, "3+4=7");
        }
    }
}
