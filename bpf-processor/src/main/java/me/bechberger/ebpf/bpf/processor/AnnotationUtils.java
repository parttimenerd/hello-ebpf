package me.bechberger.ebpf.bpf.processor;

import javax.lang.model.AnnotatedConstruct;
import javax.lang.model.element.AnnotationMirror;
import javax.lang.model.element.VariableElement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

class AnnotationUtils {

    public final static String SIZE_ANNOTATION = "me.bechberger.ebpf.annotations.Size";
    public final static String SIZES_ANNOTATION = "me.bechberger.ebpf.annotations.Sizes";
    public final static String UNSIGNED_ANNOTATION = "me.bechberger.ebpf.annotations.Unsigned";

    /**
     * Get a specific annotation which is present on the element (if not present returns {@code Optional.empty()})
     */
    static Optional<? extends AnnotationMirror> getAnnotationMirror(AnnotatedConstruct element,
                                                                    String annotationName) {
        return element.getAnnotationMirrors().stream().filter(a -> a.getAnnotationType().asElement().toString().equals(annotationName)).findFirst();
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

    record AnnotationValues(boolean unsigned, List<Integer> size) {
        AnnotationValues dropSize() {
            return new AnnotationValues(unsigned, size.subList(1, size.size()));
        }
    }

    static AnnotationValues getAnnotationValuesForRecordMember(VariableElement element) {
        return getAnnotationValuesForRecordMember(element.asType());
    }

    @SuppressWarnings("unchecked")
    static AnnotationValues getAnnotationValuesForRecordMember(AnnotatedConstruct element) {
        boolean unsigned = hasAnnotation(element, UNSIGNED_ANNOTATION);
        List<Integer> sizes = new ArrayList<>();
        var sizeAnnotation = getAnnotationMirror(element, SIZE_ANNOTATION);
        if (sizeAnnotation.isPresent()) {
            var value = sizeAnnotation.get().getElementValues().entrySet().stream().findFirst();
            if (value.isPresent()) {
                sizes = new ArrayList<>(List.of((Integer) value.get().getValue().getValue()));
            }
        }
        var sizesAnnotation = getAnnotationMirror(element, SIZES_ANNOTATION);
        if (sizesAnnotation.isPresent()) {
            sizes.addAll(((List<AnnotationMirror>)sizesAnnotation.get().getElementValues().values().stream()
                    .findFirst().get().getValue()).stream().map(a -> getAnnotationValue(a, "value", -1)).toList());
        }
        return new AnnotationValues(unsigned, sizes);
    }
}
