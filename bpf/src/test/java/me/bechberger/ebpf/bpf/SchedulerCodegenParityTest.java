// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Locks the shape of the C generated for a canonical sched-ext scheduler
 * against a checked-in golden. A change to the plugin's struct-ops
 * initializer format or field ordering has to update the golden as an
 * explicit part of the change.
 */
class SchedulerCodegenParityTest {

    @Test
    void minimalSchedulerMatchesGolden() throws Exception {
        Path generated = LocateGeneratedC.find("MinimalSchedulerImpl.c");
        String actual = normalise(Files.readString(generated));

        Path goldenPath = Path.of(
                "src/test/resources/scheduler-parity/minimal-scheduler-expected.c");
        String expected = normalise(Files.readString(goldenPath));

        assertEquals(expected, actual,
                "Generated C for MinimalScheduler drifted from the checked-in golden. "
                        + "If this change is intentional, update "
                        + goldenPath + " with the new output.");
    }

    /** Strips blank lines and trailing whitespace; preserves everything else. */
    private static String normalise(String s) {
        return s.lines()
                .map(String::stripTrailing)
                .filter(l -> !l.isBlank())
                .collect(Collectors.joining("\n"));
    }
}
