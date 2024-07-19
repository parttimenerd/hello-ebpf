package me.bechberger.ebpf.bpf.processor;

import javax.lang.model.AnnotatedConstruct;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.ArrayType;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class AnnotationUtils {

    public final static String SIZE_ANNOTATION = "me.bechberger.ebpf.annotations.Size";
    public final static String SIZES_ANNOTATION = "me.bechberger.ebpf.annotations.Sizes";
    public final static String UNSIGNED_ANNOTATION = "me.bechberger.ebpf.annotations.Unsigned";
    public final static String OFFSET_ANNOTATION = "me.bechberger.ebpf.annotations.Offset";

    /**
     * Get a specific annotation which is present on the element (if not present returns {@code Optional.empty()})
     */
    static Optional<? extends AnnotationMirror> getAnnotationMirror(AnnotatedConstruct element,
                                                                    String annotationName) {
        var annotations = getAnnotationMirrors(element, annotationName);
        if (annotations.isEmpty()) {
            return Optional.empty();
        }
        if (annotations.size() > 1) {
            throw new IllegalStateException("Multiple annotations of type " + annotationName + " found on element " + element);
        }
        return Optional.of(annotations.getFirst());
    }

    static List<? extends AnnotationMirror> getAnnotationMirrors(AnnotatedConstruct element,
                                                                    String annotationName) {
        return element.getAnnotationMirrors().stream().filter(a -> a.getAnnotationType().asElement().toString().equals(annotationName)).toList();
    }

    static Map<String, Object> getAnnotationValues(AnnotationMirror annotation) {
        return annotation.getElementValues().entrySet().stream().collect(Collectors.toMap(e -> e.getKey().toString(),
                Map.Entry::getValue));
    }

    @SuppressWarnings("unchecked")
    static <T> T getAnnotationValue(AnnotationMirror annotation, String name, T defaultValue) {
        return annotation.getElementValues().entrySet().stream().filter(e -> e.getKey().getSimpleName().toString().equals(name)).map(e -> (T) e.getValue().getValue()).findFirst().orElse(defaultValue);
    }

    static boolean hasAnnotation(AnnotatedConstruct element, String annotationName) {
        return getAnnotationMirror(element, annotationName).isPresent();
    }

    public record AnnotationValues(boolean unsigned, List<Integer> size, Optional<Integer> offset) {
        AnnotationValues dropSize() {
            return new AnnotationValues(unsigned, size.subList(1, size.size()), offset);
        }
        AnnotationValues dropOffset() {
            return new AnnotationValues(unsigned, size, Optional.empty());
        }

        enum AnnotationKind {
            SIZE,
            UNSIGNED,
            OFFSET;

            @Override
            public String toString() {
                return "@" + name().charAt(0) + name().toLowerCase().substring(1);
            }
        }

        boolean hasAnnotation(AnnotationKind kind) {
            return switch (kind) {
                case SIZE -> !size.isEmpty();
                case UNSIGNED -> unsigned;
                case OFFSET -> offset.isPresent();
            };
        }

        /** Check if the annotation has all the supported annotations */
        boolean checkSupportedAnnotations(Consumer<String> logger, AnnotationKind... supported) {
            boolean error = false;
            var supp = Arrays.asList(supported);
            for (var kind : AnnotationKind.values()) {
                if (!supp.contains(kind) && hasAnnotation(kind)) {
                    logger.accept("Unsupported annotation " + kind + " on member");
                    error = true;
                }
            }
            return !error;
        }

        public AnnotationValues addSizes(List<Integer> sizes) {
            var newSizes = new ArrayList<>(size);
            newSizes.addAll(sizes);
            return new AnnotationValues(unsigned, newSizes, offset);
        }
    }

    static AnnotationValues getAnnotationValuesForRecordMember(VariableElement element) {
        return getAnnotationValuesForRecordMember(element.asType());
    }

    @SuppressWarnings("unchecked")
    public static AnnotationValues getAnnotationValuesForRecordMember(AnnotatedConstruct element) {
        boolean unsigned = hasAnnotation(element, UNSIGNED_ANNOTATION);
        List<Integer> sizes = new ArrayList<>();
        Consumer<AnnotatedConstruct> process = con -> {
            var sizeAnnotations = getAnnotationMirrors(con, SIZE_ANNOTATION);
            for (var sizeAnnotation : sizeAnnotations) {
                var value = sizeAnnotation.getElementValues().entrySet().stream().findFirst();
                sizes.addFirst((Integer) value.orElseThrow().getValue().getValue());
            }
            var sizesAnnotations = getAnnotationMirrors(con, SIZES_ANNOTATION);
            for (var sizesAnnotation : sizesAnnotations) {
                sizes.addAll(0, ((List<AnnotationMirror>) sizesAnnotation.getElementValues().values().stream()
                        .findFirst().orElseThrow().getValue()).stream().map(a -> getAnnotationValue(a, "value", -1)).toList());
            }
        };
        process.accept(element);
        while (element instanceof ArrayType) {
            process.accept(((ArrayType) element).getComponentType());
            element = ((ArrayType) element).getComponentType();
        }
        Optional<Integer> offset = getAnnotationMirror(element, OFFSET_ANNOTATION).map(a -> getAnnotationValue(a, "value", 0));
        return new AnnotationValues(unsigned, sizes, offset);
    }
}
