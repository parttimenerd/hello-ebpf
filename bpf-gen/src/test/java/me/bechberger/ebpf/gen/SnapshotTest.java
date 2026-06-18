package me.bechberger.ebpf.gen;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Asymmetric snapshot test for generated BPF runtime helper methods.
 *
 * <p>Compares the set of "ClassName.methodName" entries the generator produces against a
 * checked-in snapshot for this kernel version. Removals and renames fail loudly; new entries
 * are logged as information only (additions are OK).
 *
 * <p>Update the snapshot for the running kernel:
 * <pre>
 *   ./mvnw -pl bpf-gen test -Dtest=SnapshotTest -Dsnapshot.update=true
 * </pre>
 */
@EnabledOnOs(OS.LINUX)
class SnapshotTest {

    private static final String UPDATE_PROPERTY = "snapshot.update";

    @Test
    void snapshotBPFHelpers() throws IOException {
        var gen = new Generator("me.bechberger.ebpf.runtime");
        gen.process();
        List<String> current = gen.publicBPFHelperSignatures();

        String kernelVersion = System.getProperty("os.version");
        // Normalise e.g. "6.17.0-35-generic" → "6.17.0-35-generic" (keep as-is; snapshot file named by full ver)
        Path snapshotDir = snapshotDir();
        Path snapshotFile = snapshotDir.resolve(kernelVersion + ".txt");

        boolean update = Boolean.parseBoolean(System.getProperty(UPDATE_PROPERTY, "false"));

        if (update || !Files.exists(snapshotFile)) {
            Files.createDirectories(snapshotDir);
            Files.writeString(snapshotFile, String.join("\n", current) + "\n");
            System.out.println("[snapshot] Wrote " + current.size() + " entries to " + snapshotFile);
            return;
        }

        List<String> snapshot = Files.readAllLines(snapshotFile).stream()
                .filter(l -> !l.isBlank())
                .sorted()
                .collect(Collectors.toList());

        var currentSet = java.util.Set.copyOf(current);
        var snapshotSet = java.util.Set.copyOf(snapshot);

        // Additions are OK — log only
        var added = current.stream().filter(e -> !snapshotSet.contains(e)).sorted().toList();
        if (!added.isEmpty()) {
            System.out.println("[snapshot] " + added.size() + " new method(s) (OK, snapshot not updated):");
            added.forEach(e -> System.out.println("  + " + e));
        }

        // Removals and renames are failures
        var removed = snapshot.stream().filter(e -> !currentSet.contains(e)).sorted().toList();
        if (!removed.isEmpty()) {
            var msg = removed.size() + " method(s) from snapshot are missing in generated output.\n" +
                    "If this is an intentional rename/removal, update the snapshot:\n" +
                    "  ./mvnw -pl bpf-gen test -Dtest=SnapshotTest -Dsnapshot.update=true\n" +
                    "and add a @Deprecated alias in bpf-gen/src/main/resources/aliases.json.\n" +
                    "Missing:\n" + removed.stream().map(e -> "  - " + e).collect(Collectors.joining("\n"));
            fail(msg);
        }

        System.out.println("[snapshot] OK — " + snapshot.size() + " methods, " + added.size() + " new, 0 removed.");
    }

    private Path snapshotDir() {
        // Maven surefire sets basedir to the module directory (where pom.xml lives).
        Path base = Paths.get(System.getProperty("basedir", ".")).toAbsolutePath();
        Path src = base.resolve("src/test/resources/snapshots");
        if (Files.isDirectory(src.getParent())) {
            return src;
        }
        // Fallback for running outside Maven
        return base.resolve("target/test-classes/snapshots");
    }
}
