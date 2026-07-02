// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

/**
 * Small helper that locates a generated-C file emitted by the BPF annotation
 * processor into {@code bpf-samples}'s {@code target/generated-sources} tree.
 * Used by codegen-parity tests that compare emitted C against a golden.
 */
final class LocateGeneratedC {

    private LocateGeneratedC() {}

    static Path find(String fileName) {
        Path root = Path.of("../bpf-samples/target/generated-sources");
        if (!Files.exists(root)) {
            throw new IllegalStateException(
                    "bpf-samples not compiled — run `mvn -pl bpf-samples compile` first (looked in "
                            + root.toAbsolutePath() + ")");
        }
        try (Stream<Path> stream = Files.walk(root)) {
            return stream.filter(p -> p.getFileName().toString().equals(fileName))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "generated C file not found under " + root.toAbsolutePath()
                                    + ": " + fileName));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
