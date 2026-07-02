package me.bechberger.ebpf.bpf.compiler.structops;

import me.bechberger.ebpf.annotations.bpf.StructOps;

import javax.annotation.processing.ProcessingEnvironment;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.ElementFilter;
import java.util.ArrayList;
import java.util.List;

/**
 * Walks a {@code @BPF} class's directly-implemented interfaces and returns
 * one {@link Kind} per interface annotated {@code @StructOps}. Indirect
 * interfaces (an interface that extends a {@code @StructOps} interface
 * without being annotated itself) are silently ignored - the spec is
 * explicit that we do not follow chains.
 */
public final class StructOpsDiscovery {

    private StructOpsDiscovery() {}

    /**
     * @param kernelName        the annotation's {@code value()} - e.g. "tcp_congestion_ops"
     * @param iface             the interface type element
     * @param sectionPrefix     annotation's {@code sectionPrefix()} - e.g. "struct_ops/"
     * @param instanceName      annotation's {@code instanceName()} - empty means use class name
     * @param overriddenMethods the interface methods the concrete class overrode.
     *                          Un-overridden defaults are excluded (kernel accepts NULL for optional slots).
     */
    public record Kind(
            String kernelName,
            TypeElement iface,
            String sectionPrefix,
            String instanceName,
            List<ExecutableElement> overriddenMethods) {}

    public static List<Kind> discover(TypeElement bpfClass, ProcessingEnvironment env) {
        List<Kind> out = new ArrayList<>();
        for (TypeMirror ifMirror : bpfClass.getInterfaces()) {
            if (!(ifMirror instanceof DeclaredType dt)) continue;
            TypeElement iface = (TypeElement) dt.asElement();
            StructOps ann = iface.getAnnotation(StructOps.class);
            if (ann == null) continue;
            List<ExecutableElement> overridden = collectOverriddenMethods(iface, bpfClass, env);
            out.add(new Kind(
                    ann.value(),
                    iface,
                    ann.sectionPrefix(),
                    ann.instanceName(),
                    overridden));
        }
        return out;
    }

    /**
     * Returns the interface methods that the concrete class overrides.
     * A default method is considered overridden if the class declares a
     * method with matching name+erasure and does NOT carry the ABSTRACT
     * modifier.
     */
    private static List<ExecutableElement> collectOverriddenMethods(
            TypeElement iface, TypeElement bpfClass, ProcessingEnvironment env) {
        var elements = env.getElementUtils();
        var declaredIn = ElementFilter.methodsIn(bpfClass.getEnclosedElements());
        List<ExecutableElement> out = new ArrayList<>();
        for (ExecutableElement m : ElementFilter.methodsIn(iface.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.STATIC)) continue;
            for (ExecutableElement candidate : declaredIn) {
                if (candidate.getModifiers().contains(Modifier.ABSTRACT)) continue;
                if (!candidate.getSimpleName().contentEquals(m.getSimpleName())) continue;
                if (elements.overrides(candidate, m, bpfClass)) {
                    out.add(m);   // return the INTERFACE method (canonical) - the concrete one is looked up by name in later stages
                    break;
                }
            }
        }
        return out;
    }
}
