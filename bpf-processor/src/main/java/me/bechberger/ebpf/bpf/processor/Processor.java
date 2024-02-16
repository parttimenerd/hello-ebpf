package me.bechberger.ebpf.bpf.processor;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import java.util.Set;

@SupportedAnnotationTypes("me.bechberger.ebpf.annotations.bpf.BPF")
@SupportedSourceVersion(SourceVersion.RELEASE_8)
public class Processor extends AbstractProcessor {
    public boolean process(Set<? extends TypeElement> annotations,
                           RoundEnvironment env) {
        annotations.forEach(annotation -> {
                    Set<? extends Element> elements = env.getElementsAnnotatedWith(annotation);
                    if (annotation.getQualifiedName().toString().equals("me.bechberger.ebpf.annotations.bpf.BPF")) {
                        elements.stream()
                                .filter(TypeElement.class::isInstance)
                                .map(TypeElement.class::cast).forEach(typeElement -> {
                                    processBPFProgram(typeElement);
                                });
                    }
                }
        );
        return true;
    }

    public void processBPFProgram(TypeElement typeElement) {
        System.out.println("Processing BPFProgram: " + typeElement.getQualifiedName());
        if (typeElement.getSuperclass() == null || !typeElement.getSuperclass().toString().equals("me.bechberger.ebpf" +
                ".bpf.BPFProgram")) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with " +
                    "BPF but does not extend BPFProgram", typeElement);
            return;
        }

    }
}
