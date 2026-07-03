package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HelloArrayOfMapsTest {

    @Test
    void arrayOfMapsDispatchesSyscallsToSlots() throws Exception {
        try (HelloArrayOfMaps program = BPFProgram.load(HelloArrayOfMaps.class)) {
            // Generate some syscalls while the tracepoint is active.
            // We start a small background thread that opens temp files to
            // produce openat/close syscalls across the observation window.
            Thread syscallGenerator = new Thread(() -> {
                try {
                    for (int i = 0; i < 50; i++) {
                        java.nio.file.Files.createTempFile("hello-aom-", ".tmp").toFile().deleteOnExit();
                        Thread.sleep(20);
                    }
                } catch (Exception ignored) {}
            });
            syscallGenerator.setDaemon(true);
            syscallGenerator.start();

            long[] totals = program.run(2);

            long grandTotal = 0;
            for (long t : totals) grandTotal += t;
            assertTrue(grandTotal > 0,
                    "expected at least one syscall across all slots, got 0");

            // Verify unregister clears a slot.
            program.outerMap.unregister(0);
            assertNull(program.outerMap.get(0), "unregister(0) should clear slot 0");
        }
    }
}
