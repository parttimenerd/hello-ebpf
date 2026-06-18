package me.bechberger.ebpf.bpf.processor;

import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * Cache compilation results on disk, makes builds far faster.
 */
public class CompilationCache {

    private static final String CACHE_FOLDER_NAME = ".bpf.compile.cache";
    private static final int MAX_DAYS_TO_KEEP_CACHE = 30;
    private static final long MAX_CACHE_SIZE_IN_BYTES = 200_000_000L;
    private static boolean cleaned = false;

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
        if (!cleaned) {
            cleaned = true;
            cleanOldFiles();
        }
    }

    public byte @Nullable [] getCached(String cProgram) {
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
                // never delete vmlinux.h — it's expensive to regenerate and not an .o
                if (p.getFileName().toString().equals("vmlinux.h")) return;
                try {
                    long ageMs = System.currentTimeMillis() - Files.getLastModifiedTime(p).toMillis();
                    if (ageMs > (long) MAX_DAYS_TO_KEEP_CACHE * 24 * 60 * 60 * 1000) {
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
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] hash = digest.digest(cProgram.getBytes());
        return cacheFolder.resolve(Base64.getEncoder().encodeToString(hash).replaceAll("[^A-Za-z0-9_]", "") + ".o");
    }

    public void cache(String cProgram, byte[] objectFile) {
        Path file = fileName(cProgram);
        removeFilesTill(objectFile.length);
        try {
            // Write atomically via a temp file so a partial write or a pre-existing
            // file owned by another user (e.g. from a prior sudo build) never leaves
            // a corrupt or inaccessible cache entry.
            Path tmp = Files.createTempFile(cacheFolder, "ebpf-cache-", ".tmp");
            try {
                Files.write(tmp, objectFile);
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void removeFilesTill(long emptySpace) {
        long currentSize = size();
        long toRemove = currentSize + emptySpace - MAX_CACHE_SIZE_IN_BYTES;
        if (toRemove <= 0) {
            return;
        }
        // evict only .o files (never vmlinux.h) ordered oldest-first
        var files = cachedFiles().stream()
                .filter(p -> p.getFileName().toString().endsWith(".o"))
                .sorted((p1, p2) -> {
                    try {
                        return Long.compare(Files.getLastModifiedTime(p1).toMillis(),
                                            Files.getLastModifiedTime(p2).toMillis());
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

    private long size() {
        return cachedFiles().stream().mapToLong(p -> {
            try {
                return Files.size(p);
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

    public Path getCacheFolder() {
        return cacheFolder;
    }
}
