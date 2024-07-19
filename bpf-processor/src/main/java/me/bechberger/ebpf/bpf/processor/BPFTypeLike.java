package me.bechberger.ebpf.bpf.processor;

import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Declarator.StructIdentifierDeclarator;
import me.bechberger.cast.CAST.Declarator.UnionIdentifierDeclarator;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.BPFName;
import me.bechberger.ebpf.bpf.processor.DefinedTypes.JavaName;
import me.bechberger.ebpf.type.BPFType;
import me.bechberger.ebpf.type.BPFType.*;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Typedef;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;

import java.util.function.Function;

public interface BPFTypeLike<T> {

    @Nullable
    DefinedTypes.SpecFieldName getSpecFieldName(DefinedTypes types);

    JavaName getJavaName();

    BPFName getBPFName();

    String getBPFNameWithStructPrefixIfNeeded();

    String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName);

    String toJavaUse();

    String toJavaUseInGenerics();

    final class VerbatimBPFOnlyType<T> implements BPFTypeLike<T> {

        public enum PrefixKind {
            STRUCT,
            UNION,
            ENUM,
            NORMAL
        }

        final String bpfName;
        final PrefixKind prefixKind;

        public VerbatimBPFOnlyType(String bpfName, PrefixKind prefixKind) {
            this.bpfName = bpfName;
            this.prefixKind = prefixKind;
        }

        @Override
        public DefinedTypes.SpecFieldName getSpecFieldName(DefinedTypes types) {
            throw new UnsupportedOperationException();
        }

        @Override
        public JavaName getJavaName() {
            throw new UnsupportedOperationException();
        }

        @Override
        public BPFName getBPFName() {
            return new BPFName(bpfName);
        }

        @Override
        public String getBPFNameWithStructPrefixIfNeeded() {
            return switch (prefixKind) {
                case STRUCT -> "struct " + bpfName;
                case UNION -> "union " + bpfName;
                case ENUM -> "enum " + bpfName;
                case NORMAL -> bpfName;
            };
        }

        @Override
        public String toJavaFieldSpecUse(Function<BPFType<?>, String> typeToSpecFieldName) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String toJavaUse() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String toJavaUseInGenerics() {
            throw new UnsupportedOperationException();
        }

        @Override
        public CustomBPFType<T> toCustomType() {
            return new CustomBPFType<>(null, null, null, bpfName, () -> {
                var name = CAST.Expression.variable(bpfName);
                return switch (prefixKind) {
                    case STRUCT -> new StructIdentifierDeclarator(name);
                    case UNION -> new UnionIdentifierDeclarator(name);
                    case ENUM -> new CAST.Declarator.EnumIdentifierDeclarator(name);
                    case NORMAL -> new CAST.Declarator.IdentifierDeclarator(name);
                };
            }, null, null);
        }
    }

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
            return new CustomBPFType<>(getJavaName().name(), toJavaUse(), toJavaUseInGenerics(), type.bpfName(), type::toCUse, type::toJavaFieldSpecUse,
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
        public String toJavaUseInGenerics() {
            return type.toJavaUseInGenerics();
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

    final class TypeBackedBPFUnionType<T extends Union> extends TypeBackedBPFTypeLike<T> {

        public TypeBackedBPFUnionType(BPFUnionType<T> type) {
            super(type);
        }
    }

    final class TypeBackedBPFTypedef<W, T extends Typedef<W>> extends TypeBackedBPFTypeLike<T> {

        public TypeBackedBPFTypedef(BPFTypedef<W, T> type) {
            super(type);
        }
    }

    final class TypeBackedBPFEnumType<T extends Enum<?>> extends TypeBackedBPFTypeLike<T> {

        public TypeBackedBPFEnumType(BPFEnumType<T> type) {
            super(type);
        }
    }

    CustomBPFType<T> toCustomType();
}
