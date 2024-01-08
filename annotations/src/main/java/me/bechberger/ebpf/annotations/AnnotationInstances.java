package me.bechberger.ebpf.annotations;

public class AnnotationInstances {
    public static final Unsigned UNSIGNED = new Unsigned() {
        @Override
        public Class<? extends java.lang.annotation.Annotation> annotationType() {
            return Unsigned.class;
        }
    };
}
