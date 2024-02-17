// SPDX-License-Identifier: Apache-2.0

package me.bechberger.ebpf.bpf.raw;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Loads the BPF library
 */
public class LibraryLoader {


    private static Optional<Path> findLibInFolder(Path folder, int depth) {
        try (var stream = Files.walk(folder, depth, FileVisitOption.FOLLOW_LINKS)) {
            return stream.filter(p -> p.getFileName().toString().startsWith("libbpf.so")).findFirst();
        } catch (IOException e) {
            return Optional.empty();
        }
    }
    private static Optional<Path> findBPFLibrary() {
        var javaLibraryPath = System.getProperty("java.library.path");
        if (javaLibraryPath == null) {
            return Optional.empty();
        }

        return Arrays.stream(javaLibraryPath.split(":"))
                .map(f -> findLibInFolder(Path.of(f), 1))
                .filter(Optional::isPresent).map(Optional::get).findFirst()
                .or(() -> Stream.of("/lib", "/usr/lib", "/lib64", "/usr/lib64")
                        .map(Path::of)
                        .map(p -> findLibInFolder(p, 2))
                        .filter(Optional::isPresent).map(Optional::get).findFirst());
    }

    /**
     * Checks if the BPF library is available
     */
    public static boolean isInstalled() {
        return findBPFLibrary().isPresent();
    }

    /**
     * Loads the BPF library and {@code System.exit(1)} if it is not available
     */
    public static void load() {
        try {
            System.loadLibrary("bpf");
        } catch (UnsatisfiedLinkError e) {
            var lib = findBPFLibrary();
            if (lib.isPresent()) {
                System.load(lib.get().toString());
                return;
            }
            System.err.println("Failed to load libbpf.so, pass the location of the lib folder " +
                    "via -Djava.library.path after you installed it");
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        System.out.println(isInstalled());
    }
}