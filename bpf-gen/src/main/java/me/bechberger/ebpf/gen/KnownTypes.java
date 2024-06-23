package me.bechberger.ebpf.gen;

import com.squareup.javapoet.AnnotationSpec;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.TypeName;
import me.bechberger.cast.CAST.Declarator;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.type.BPFType.BPFIntType;
import me.bechberger.ebpf.type.BPFType.BPFIntType.Int128;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static me.bechberger.ebpf.gen.Generator.cts;

public class KnownTypes {

    private static final Logger logger = Logger.getLogger(KnownTypes.class.getName());

    record JavaType(TypeName type, @Nullable TypeName inGenerics) {

        static JavaType create(TypeName type, Class<?> inGenerics) {
            return new JavaType(type, TypeName.get(inGenerics));
        }

        static JavaType createUnsigned(TypeName type, Class<?> inGenerics) {
            return new JavaType(addUnsignedAnnotation(type), addUnsignedAnnotation(TypeName.get(inGenerics)));
        }

        private static TypeName addUnsignedAnnotation(TypeName type) {
            return type.annotated(AnnotationSpec.builder(cts(Unsigned.class)).build());
        }
    }

    /**
     * Integer (and float for simplicity) type with known properties, with is mapped to a Java type.
     */
    public record KnownInt(String cName, int bits, String encoding, KnownTypes.JavaType javaType, BPFIntType<?> bpfType) {
        boolean isSigned() {
            return encoding.equals("SIGNED");
        }

        public Declarator toCType() {
            return Declarator.identifier(cName);
        }
    }

    private static final KnownInt[] knownInts = {
            new KnownInt("_Bool", 8, "BOOL", JavaType.create(TypeName.BOOLEAN, Boolean.class), BPFIntType.BOOL),
            new KnownInt("char", 8, "(none)", JavaType.create(TypeName.CHAR, Character.class), BPFIntType.CHAR),
            new KnownInt("signed char", 8, "SIGNED", JavaType.create(TypeName.BYTE, Byte.class),
                    BPFIntType.SIGNED_CHAR),
            new KnownInt("unsigned char", 8, "(none)", JavaType.createUnsigned(TypeName.CHAR, Character.class),
                    BPFIntType.CHAR),
            new KnownInt("short int", 16, "SIGNED", JavaType.create(TypeName.SHORT, Short.class), BPFIntType.INT16),
            new KnownInt("short unsigned int", 16, "(none)", JavaType.createUnsigned(TypeName.SHORT, Short.class),
                    BPFIntType.UINT16),
            new KnownInt("int", 32, "SIGNED", JavaType.create(TypeName.INT, Integer.class), BPFIntType.INT32),
            new KnownInt("unsigned int", 32, "(none)", JavaType.createUnsigned(TypeName.INT, Integer.class),
                    BPFIntType.UINT32),
            new KnownInt("long int", 64, "SIGNED", JavaType.create(TypeName.LONG, Long.class), BPFIntType.INT64),
            new KnownInt("long unsigned int", 64, "(none)", JavaType.createUnsigned(TypeName.LONG, Long.class),
                    BPFIntType.UINT64),
            new KnownInt("long long int", 64, "SIGNED", JavaType.create(TypeName.LONG, Long.class), BPFIntType.INT64),
            new KnownInt("long long unsigned int", 64, "(none)", JavaType.createUnsigned(TypeName.LONG, Long.class),
                    BPFIntType.UINT64),
            new KnownInt("__int128", 128, "SIGNED", JavaType.create(ClassName.get(Int128.class), Int128.class),
                    BPFIntType.INT128),
            new KnownInt("__int128 unsigned", 128, "(none)", JavaType.createUnsigned(ClassName.get(Int128.class),
                    Int128.class), BPFIntType.UINT128),
            new KnownInt("ssizetype", 64, "SIGNED", JavaType.create(TypeName.LONG, Long.class), BPFIntType.INT64),
            new KnownInt("float", 32, "(none)", JavaType.create(TypeName.FLOAT, Float.class), BPFIntType.FLOAT),
            new KnownInt("double", 64, "(none)", JavaType.create(TypeName.DOUBLE, Double.class), BPFIntType.DOUBLE)
    };

    private static final Map<String, KnownTypes.KnownInt> cNameToKnownInt = Arrays.stream(knownInts)
            .collect(Collectors.toMap(KnownInt::cName, Function.identity()));

    /**
     * Get the known int type for the given C name.
     *
     * @param cName    the C name
     * @param bits     the number of bytes, to check for compatibility
     * @param encoding the encoding, to check for compatibility
     * @return the known int type, if it exists
     */
    static Optional<KnownInt> getKnownInt(String cName, int bits, String encoding) {
        if (cNameToKnownInt.containsKey(cName)) {
            var knownInt = cNameToKnownInt.get(cName);
            if (knownInt.bits() == bits && knownInt.encoding().equals(encoding)) {
                return Optional.of(knownInt);
            } else {
                // log differing properties
                logger.warning("Known int type " + cName + " has differing properties: " + knownInt.bits() + " bits " +
                        "and " + knownInt.encoding() + " encoding, not " + bits + " bits and " + encoding + " " +
                        "encoding");
            }
        }
        return Optional.empty();
    }

    static Optional<KnownInt> getKnownInt(int bits, boolean signed) {
        return Arrays.stream(knownInts)
                .filter(knownInt -> knownInt.bits() == bits && knownInt.isSigned() == signed)
                .findFirst();
    }

    /**
     * works with non-normalized names
     */
    static KnownInt getKnowIntUnchecked(String cName) {
        return Objects.requireNonNull(cNameToKnownInt.get(normalizeNames(cName)));
    }

    /**
     * works with non-normalized names
     */
    static boolean isKnownInt(String cName) {
        return cNameToKnownInt.containsKey(normalizeNames(cName));
    }

    /**
     * Return the proper name for {@ocode s32, u16, __u64, ...}
     */
    static String normalizeNames(String name) {
        if (name.matches("(__)?[suSU][0-9]+")) {
            boolean isUnsigned = name.contains("u");
            int width = Integer.parseInt(name.split("[suSU]")[1]);
            return getKnownInt(width, !isUnsigned).orElseThrow().cName();
        }
        return switch (name) {
            case "unsigned long" -> "long unsigned int";
            case "long" -> "long int";
            case "size_t" -> "long unsigned int";
            default -> name;
        };
    }
}
