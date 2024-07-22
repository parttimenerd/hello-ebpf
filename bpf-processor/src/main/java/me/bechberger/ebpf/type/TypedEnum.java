package me.bechberger.ebpf.type;

/**
 * Helps to specify the type of the variables of an enum
 */
public interface TypedEnum<T extends java.lang.Enum<T> & TypedEnum<T, V> & Enum<T>, V> {

}
