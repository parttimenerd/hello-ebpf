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
     * @param kernelName         the annotation's {@code value()} - e.g. "tcp_congestion_ops"
     * @param iface              the interface type element
     * @param sectionPrefix      annotation's {@code sectionPrefix()} - e.g. "struct_ops/"
     * @param instanceName       annotation's {@code instanceName()} - empty means use class name
     * @param emittedNamePrefix  annotation's {@code emittedNamePrefix()} - prepended to each emitted
     *                           BPF function symbol and the {@code (void *)<name>} side of initializers
     * @param overriddenMethods  the interface methods the concrete class overrode.
     *                           Un-overridden defaults are excluded (kernel accepts NULL for optional slots).
     */
    public record Kind(
            String kernelName,
            TypeElement iface,
            String sectionPrefix,
            String instanceName,
            String emittedNamePrefix,
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
                    ann.emittedNamePrefix(),
                    overridden));
        }
        return out;
    }

    /**
     * Returns the interface methods that the concrete class overrides.
     * A default method is considered overridden if the class or any of its
     * non-Object ancestors declares a concrete method with matching name+erasure.
     * Most-derived declaration wins; the INTERFACE method element is returned
     * so downstream stages use the canonical (interface) element.
     */
    private static List<ExecutableElement> collectOverriddenMethods(
            TypeElement iface, TypeElement bpfClass, ProcessingEnvironment env) {
        var elements = env.getElementUtils();
        // Walk bpfClass and all its non-Object ancestors, gathering concrete methods.
        // concreteChain is ordered bpfClass -> super, so the first candidate that
        // overrides an interface method is the most-derived declaration.
        List<ExecutableElement> concreteChain = new ArrayList<>();
        TypeElement cursor = bpfClass;
        while (cursor != null) {
            if (cursor.getQualifiedName().contentEquals("java.lang.Object")) break;
            for (ExecutableElement m : ElementFilter.methodsIn(cursor.getEnclosedElements())) {
                if (m.getModifiers().contains(Modifier.ABSTRACT)) continue;
                concreteChain.add(m);
            }
            TypeMirror sup = cursor.getSuperclass();
            cursor = (sup instanceof DeclaredType d) ? (TypeElement) d.asElement() : null;
        }
        List<ExecutableElement> out = new ArrayList<>();
        for (ExecutableElement m : ElementFilter.methodsIn(iface.getEnclosedElements())) {
            if (m.getModifiers().contains(Modifier.STATIC)) continue;
            for (ExecutableElement candidate : concreteChain) {
                if (!candidate.getSimpleName().contentEquals(m.getSimpleName())) continue;
                if (elements.overrides(candidate, m, (TypeElement) candidate.getEnclosingElement())) {
                    out.add(m);   // return the INTERFACE method (canonical) - the concrete one is looked up by name in later stages
                    break;  // most-derived wins (concreteChain ordered bpfClass -> super)
                }
            }
        }
        return out;
    }
}
