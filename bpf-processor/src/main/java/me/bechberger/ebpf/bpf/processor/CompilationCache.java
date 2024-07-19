package me.bechberger.ebpf.bpf.processor;

import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * Cache compilation results on disk, makes builds far faster.
 */
public class CompilationCache {

    private static final String CACHE_FOLDER_NAME = ".bpf.compile.cache";
    private static final int MAX_DAYS_TO_KEEP_CACHE = 7;
    private static final int MAX_CACHE_SIZE_IN_BYTES = 10_000_000;

    private final Path cacheFolder;

    public CompilationCache(Path baseFolder) {
        this.cacheFolder = baseFolder.resolve(CACHE_FOLDER_NAME);
        if (!this.cacheFolder.toFile().exists()) {
            try {
                Files.createDirectories(this.cacheFolder);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        cleanOldFiles();
    }

    public  byte @Nullable [] getCached(String cProgram) {
        Path file = fileName(cProgram);
        if (!file.toFile().exists()) {
            return null;
        }
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void cleanOldFiles() {
        try (var list = Files.list(cacheFolder)) {
            list.forEach(p -> {
                try {
                    if (Files.getLastModifiedTime(p).toMillis() < System.currentTimeMillis() - MAX_DAYS_TO_KEEP_CACHE * 24 * 60 * 60 * 1000) {
                        Files.delete(p);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private Path fileName(String cProgram) {
        // compute hash of cProgram
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        // encode in base 64
        byte[] hash = digest.digest(cProgram.getBytes());
        return cacheFolder.resolve(Base64.getEncoder().encodeToString(hash).replaceAll("[^A-Za-z0-9_]", "") + ".o");
    }

    public void cache(String cProgram, byte[] objectFile) {
        Path file = fileName(cProgram);
        removeFilesTill(objectFile.length);
        try {
            Files.createFile(file);
            Files.write(file, objectFile);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void removeFilesTill(int emptySpace) {
        int currentSize = size();
        long toRemove =  currentSize + emptySpace - MAX_CACHE_SIZE_IN_BYTES;
        if (toRemove <= 0) {
            return;
        }
        var files = cachedFiles().stream().sorted((p1, p2) -> {
            try {
                return Long.compare(Files.getLastModifiedTime(p1).toMillis(), Files.getLastModifiedTime(p2).toMillis());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).toList();
        try {
            for (var file : files) {
                toRemove -= Files.size(file);
                Files.delete(file);
                if (toRemove <= 0) {
                    return;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private int size() {
        return cachedFiles().stream().mapToInt(p -> {
            try {
                return (int) Files.size(p);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).sum();
    }

    private List<Path> cachedFiles() {
        try (var list = Files.list(cacheFolder)) {
            return list.toList();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
