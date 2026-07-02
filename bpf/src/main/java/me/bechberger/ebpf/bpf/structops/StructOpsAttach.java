package me.bechberger.ebpf.bpf.structops;

import me.bechberger.ebpf.bpf.BPFProgram;

import java.util.ArrayList;
import java.util.List;

/**
 * Walks a {@code BPFProgram}'s companion {@link StructOpsManifest} and
 * attaches each declared struct_ops instance. Called by
 * {@link BPFProgram#load(Class)} after {@code bpf_object__load}.
 *
 * <p>Idempotent -- a second call sees the recorded {@link StructOpsInfo}
 * for the map (via {@code program.structOpsInfo()}) and no-ops.
 */
public final class StructOpsAttach {

    private StructOpsAttach() {}

    public static List<StructOpsInfo> attachAll(BPFProgram program) {
        var manifest = loadManifest(program);
        if (manifest == null) return List.of();

        var already = program.structOpsInfo();
        if (already != null && !already.isEmpty()) return already;

        List<StructOpsInfo> attached = new ArrayList<>();
        for (var e : manifest.entries()) {
            program.enforceStructOpsFeature(e.kernelName(), e.since());
            program.attachStructOps(e.mapName());
            int fd = program.getMapDescriptorByName(e.mapName()).fd();
            attached.add(new StructOpsInfo(
                    e.kernelName(),
                    e.mapName(),
                    fd,
                    program.lastAttachedStructOpsLinkId()));
        }
        return attached;
    }

    private static StructOpsManifest loadManifest(BPFProgram program) {
        Class<?> userClass = program.getUserClass();
        if (userClass == null) return null;
        String fqn = userClass.getName() + "StructOpsManifest";
        try {
            Class<?> mCls = Class.forName(fqn, true, userClass.getClassLoader());
            return (StructOpsManifest) mCls.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            return null;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "failed to load " + fqn + " -- this is a plugin bug", e);
        }
    }
}
