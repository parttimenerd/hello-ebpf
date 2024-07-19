package me.bechberger.ebpf.type;

import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeMirror;
import javax.lang.model.util.Elements;
import javax.lang.model.util.Types;

public class TypeUtils {

    private final Types types;
    private final Elements elements;

    public TypeUtils(Types types, Elements elements) {
        this.types = types;
        this.elements = elements;
    }

    public TypeMirror getTypeMirror(Class<?> klass) {
        return elements.getTypeElement(klass.getCanonicalName()).asType();
    }

    public boolean hasSuperClass(Element element, Class<?> klass) {
        return types.isSameType(((TypeElement) element).getSuperclass(), getTypeMirror(klass));
    }

    public boolean hasClassIgnoringTypeParameters(Element element, String klass) {
        return types.erasure(element.asType()).toString().equals(klass);
    }

    public boolean hasSameSuperclassIgnoringTypeParameters(Element element, Class<?> klass) {
        return types.isSameType(
                types.erasure(((TypeElement) element).getSuperclass()),
                types.erasure(getTypeMirror(klass)));
    }

    public boolean implementsInterface(Element element, Class<?> klass) {
        return ((TypeElement) element).getInterfaces().stream().anyMatch(t -> types.isSameType(t, getTypeMirror(klass)));
    }

    public boolean implementsInterfaceIgnoringTypeParameters(Element element, Class<?> klass) {
        var erasedKlass = types.erasure(getTypeMirror(klass));
        return ((TypeElement) element).getInterfaces().stream().anyMatch(t -> types.isSameType(
                types.erasure(t), erasedKlass));
    }
}