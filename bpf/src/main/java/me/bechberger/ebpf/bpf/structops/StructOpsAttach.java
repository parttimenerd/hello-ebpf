package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.util.json.JSONParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads a {@code BPFProgram}'s {@code META-INF/ebpf-struct-ops/<userClass>.json}
 * resource (emitted by the compiler plugin at build time) and attaches each
 * declared struct_ops instance. Called by {@code BPFProgram#load(Class)} after
 * {@code bpf_object__load}.
 *
 * <p>Idempotent -- a second call sees the recorded {@link StructOpsInfo} for
 * the map (via {@code program.structOpsInfo()}) and no-ops.
 *
 * <p>Uses the same JSON-resource pattern as the {@code @SharedFrom} processor
 * ({@code META-INF/ebpf-shared-from/*.json}). Chosen over a companion Java
 * class because the plugin runs at {@code TaskEvent.ANALYZE} which is after
 * annotation-processing rounds close -- {@code Filer.createSourceFile} at that
 * point writes the file but javac no longer compiles it, whereas
 * {@code Filer.createResource(CLASS_OUTPUT, ...)} still packages it.
 */
public final class StructOpsAttach {

    private StructOpsAttach() {}

    public static List<StructOpsInfo> attachAll(BPFProgram program) {
        var entries = loadManifestEntries(program);
        if (entries.isEmpty()) return List.of();

        var already = program.structOpsInfo();
        if (already != null && !already.isEmpty()) return already;

        List<StructOpsInfo> attached = new ArrayList<>();
        for (var e : entries) {
            program.enforceStructOpsFeature(e.kernelName(), e.since());
            program.attachStructOps(e.mapName());
            int fd = program.getMapDescriptorByName(e.mapName()).fd();
            attached.add(new StructOpsInfo(
                    e.kernelName(), e.mapName(), fd,
                    program.lastAttachedStructOpsLinkId()));
        }
        return attached;
    }

    /** Parsed entry from the JSON manifest resource. */
    record ManifestEntry(String kernelName, String mapName, String since) {}

    private static List<ManifestEntry> loadManifestEntries(BPFProgram program) {
        Class<?> userClass = program.getUserClass();
        if (userClass == null) return List.of();
        String resource = "META-INF/ebpf-struct-ops/" + userClass.getName() + ".json";
        try (InputStream in = userClass.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) return List.of();
            byte[] bytes;
            try (var buf = new ByteArrayOutputStream()) {
                in.transferTo(buf);
                bytes = buf.toByteArray();
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> root = (Map<String, Object>) JSONParser.parse(
                    new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
            @SuppressWarnings("unchecked")
            List<Object> entries = (List<Object>) root.get("entries");
            if (entries == null) return List.of();
            List<ManifestEntry> out = new ArrayList<>(entries.size());
            for (Object o : entries) {
                @SuppressWarnings("unchecked")
                Map<String, Object> e = (Map<String, Object>) o;
                out.add(new ManifestEntry(
                        (String) e.get("kernelName"),
                        (String) e.get("mapName"),
                        (String) e.get("since")));
            }
            return out;
        } catch (IOException ioe) {
            throw new IllegalStateException("failed to read " + resource, ioe);
        }
    }
}
