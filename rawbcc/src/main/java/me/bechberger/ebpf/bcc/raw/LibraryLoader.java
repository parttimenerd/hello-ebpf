// SPDX-License-Identifier: Apache-2.0

package me.bechberger.ebpf.bcc.raw;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

/**
 * Loads the BCC library
 */
public class LibraryLoader {

    private static Optional<Path> findBCCLibrary() {
        var javaLibraryPath = System.getProperty("java.library.path");
        if (javaLibraryPath == null) {
            return Optional.empty();
        }

        var paths = javaLibraryPath.split(":");
        for (var path : paths) {
            var libPath = Path.of(path + "/libbcc.so");
            if (libPath.toFile().exists()) {
                return Optional.of(libPath);
            }
        }

        try (var stream = Files.walk(Path.of("/lib"), 2, FileVisitOption.FOLLOW_LINKS)) {
            return stream.filter(p -> p.endsWith("libbcc.so")).findFirst();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Checks if the BCC library is available
     */
    public static boolean isInstalled() {
        return findBCCLibrary().isPresent();
    }

    /**
     * Loads the BCC library and {@code System.exit(1)} if it is not available
     */
    public static void load() {
        var lib = findBCCLibrary();
        if (lib.isPresent()) {
            System.load(lib.get().toString());
            return;
        }
        System.err.println("Failed to load libbcc.so, pass the location of the lib folder " +
                "via -Djava.library.path after you installed it");
        System.exit(1);
    }
}