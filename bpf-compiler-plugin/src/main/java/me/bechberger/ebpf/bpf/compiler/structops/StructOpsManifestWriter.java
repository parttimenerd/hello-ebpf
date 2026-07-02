package me.bechberger.ebpf.bpf.compiler.structops;

import javax.lang.model.element.TypeElement;
import java.util.List;

/**
 * Emits a public final class next to {@code BPFImpl} that implements
 * {@code StructOpsManifest}. The runtime uses it as an SPI to know which
 * struct_ops instances to attach without reflection.
 *
 * <p>File shape (example for a class {@code p.Cc}):
 * <pre>{@code
 * package p;
 * public final class CcStructOpsManifest
 *     implements me.bechberger.ebpf.bpf.structops.StructOpsManifest {
 *     private static final java.util.List<me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry> ENTRIES = java.util.List.of(
 *         new me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry("tcp_congestion_ops", "Cc", "5.6")
 *     );
 *     public java.util.List<me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry> entries() { return ENTRIES; }
 * }
 * }</pre>
 */
public final class StructOpsManifestWriter {

    /**
     * @param bpfClass      the user's {@code @BPF} class
     * @param instances     one {@link StructOpsSynthesizer.SynthInstance} per interface
     * @param layoutsByKind kernel-name → layout (for {@code since} lookup)
     * @return              the Java source text to write to
     *                      {@code <package>/<ClassName>StructOpsManifest.java}
     */
    public String render(TypeElement bpfClass,
                         List<StructOpsSynthesizer.SynthInstance> instances,
                         java.util.Map<String, StructOpsLayout> layoutsByKind) {
        String pkg = pkg(bpfClass);
        String className = bpfClass.getSimpleName().toString() + "StructOpsManifest";
        StringBuilder sb = new StringBuilder();
        if (!pkg.isEmpty()) sb.append("package ").append(pkg).append(";\n\n");
        sb.append("public final class ").append(className)
          .append(" implements me.bechberger.ebpf.bpf.structops.StructOpsManifest {\n");
        sb.append("    private static final java.util.List<me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry> ENTRIES = java.util.List.of(\n");
        for (int i = 0; i < instances.size(); i++) {
            var inst = instances.get(i);
            String since = layoutsByKind.get(inst.kernelName()).since();
            sb.append("        new me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry(\"").append(inst.kernelName()).append("\", \"")
              .append(inst.mapName()).append("\", \"").append(since).append("\")");
            if (i + 1 < instances.size()) sb.append(",");
            sb.append("\n");
        }
        sb.append("    );\n");
        sb.append("    public java.util.List<me.bechberger.ebpf.bpf.structops.StructOpsManifest.Entry> entries() { return ENTRIES; }\n");
        sb.append("}\n");
        return sb.toString();
    }

    private String pkg(TypeElement bpfClass) {
        // Walk up through any enclosing types (nested @BPF classes) until we
        // hit the containing PackageElement. Nested @BPF classes are common
        // in tests, so `bpfClass.getEnclosingElement()` may return another
        // TypeElement rather than the package directly.
        javax.lang.model.element.Element e = bpfClass.getEnclosingElement();
        while (e != null && !(e instanceof javax.lang.model.element.PackageElement)) {
            e = e.getEnclosingElement();
        }
        return (e instanceof javax.lang.model.element.PackageElement pe)
                ? pe.getQualifiedName().toString()
                : "";
    }
}
