package me.bechberger.ebpf.annotations;

public class AnnotationInstances {
    public static final Unsigned UNSIGNED = new Unsigned() {
        @Override
        public Class<? extends java.lang.annotation.Annotation> annotationType() {
            return Unsigned.class;
        }
    };

    public static Size size(int value) {
        return new Size() {
            @Override
            public Class<? extends java.lang.annotation.Annotation> annotationType() {
                return Size.class;
            }

            @Override
            public int value() {
                return value;
            }
        };
    }
}
