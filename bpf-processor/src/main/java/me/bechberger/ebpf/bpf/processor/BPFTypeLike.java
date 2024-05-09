package me.bechberger.ebpf.bpf.processor;

import me.bechberger.cast.CAST;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.BPFName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.JavaName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.SpecFieldName;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.BPFArrayType;
import me.bechberger.ebpf.type.BPFType.BPFStructType;
import me.bechberger.ebpf.type.BPFType.CustomBPFType;
import org.jetbrains.annotations.Nullable;

import java.util.Optional;
import java.util.function.Function;

import static me.bechberger.cast.CAST.Statement.verbatim;

sealed interface BPFTypeLike<T> {

    @Nullable
    DefinedTypes.SpecFieldName getSpecFieldName(DefinedTypes types);

    JavaName getJavaName();

    BPFName getBPFName();

    String getBPFNameWithStructPrefixIfNeeded();

    String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName);

    String toJavaUse();

    static <T> BPFTypeLike<T> of(BPFType<T> type) {
        return switch (type) {
            case BPFType.BPFStructType<T> structType -> new TypeBackedBPFStructType<>(structType);
            default -> new TypeBackedBPFTypeLike<>(type);
        };
    }

    public sealed class TypeBackedBPFTypeLike<T> implements BPFTypeLike<T> {

        final BPFType<T> type;

        public TypeBackedBPFTypeLike(BPFType<T> type) {
            this.type = type;
        }

        @Override
        public @Nullable DefinedTypes.SpecFieldName getSpecFieldName(DefinedTypes types) {
            return types.getSpecFieldName(new BPFName(type.bpfName())).orElseThrow(() -> new IllegalStateException("No spec field name for " + type.bpfName()));
        }

        @Override
        public CustomBPFType<T> toCustomType() {
            return new CustomBPFType<>(getJavaName().name(), toJavaUse(), type.bpfName(), type::toCUse, type::toJavaFieldSpecUse,
                    type::toCDeclarationStatement);
        }

        @Override
        public JavaName getJavaName() {
            return new JavaName(type);
        }

        @Override
        public String toJavaUse() {
            return type.toJavaUse();
        }

        @Override
        public BPFName getBPFName() {
            return new BPFName(type.bpfName());
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            return type.toJavaFieldSpecUse(typeToSpecFieldName);
        }

        @Override
        public String getBPFNameWithStructPrefixIfNeeded() {
            return type.toCUse().toPrettyString();
        }
    }

    final class TypeBackedBPFStructType<T> extends TypeBackedBPFTypeLike<T> {

        public TypeBackedBPFStructType(BPFStructType<T> type) {
            super(type);
        }
    }

    CustomBPFType<T> toCustomType();
}
