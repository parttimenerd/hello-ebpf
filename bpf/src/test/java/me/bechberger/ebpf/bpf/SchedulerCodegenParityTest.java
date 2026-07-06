// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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

    /**
     * Strips blank lines and trailing whitespace, then sorts top-level
     * function/SEC blocks so that non-deterministic HashMap iteration
     * order in the plugin does not cause spurious test failures.
     * The struct_ops initializer and #include preamble are kept in place.
     */
    private static String normalise(String s) {
        // 1. Strip blank lines / trailing whitespace
        List<String> lines = s.lines()
                .map(String::stripTrailing)
                .filter(l -> !l.isBlank())
                .collect(Collectors.toCollection(ArrayList::new));

        // 2. Split into top-level "blocks" separated by function boundaries.
        //    A block starts at a line that begins a function definition or SEC declaration.
        //    Everything up to the first such line is the "preamble" (includes, defines, forward decls).
        //    The struct_ops initializer at the end is the "trailer".
        List<String> preamble = new ArrayList<>();
        List<String> trailer = new ArrayList<>();
        List<List<String>> blocks = new ArrayList<>();

        List<String> current = preamble;
        boolean inFunctions = false;
        boolean inTrailer = false;

        for (String line : lines) {
            boolean isFuncStart = (line.startsWith("__always_inline") || line.startsWith("SEC("))
                    && (line.endsWith("{") || line.contains(") {") || line.endsWith("__ksym;") == false && line.contains("{"));
            boolean isTrailerStart = line.equals("SEC(\".struct_ops.link\")");

            if (isTrailerStart) {
                inTrailer = true;
                current = trailer;
                current.add(line);
            } else if (!inTrailer && isFuncStart) {
                if (!inFunctions) {
                    inFunctions = true;
                }
                current = new ArrayList<>();
                blocks.add(current);
                current.add(line);
            } else {
                current.add(line);
            }
        }

        // 3. Sort the function blocks by their first line (stable alphabetical)
        Collections.sort(blocks, (a, b) -> a.get(0).compareTo(b.get(0)));

        // 4. Reassemble
        List<String> result = new ArrayList<>(preamble);
        for (List<String> block : blocks) {
            result.addAll(block);
        }
        result.addAll(trailer);

        return String.join("\n", result);
    }
}
