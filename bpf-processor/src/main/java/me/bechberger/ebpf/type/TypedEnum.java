package me.bechberger.ebpf.type;

import me.bechberger.ebpf.annotations.bpf.EnumMember;
import org.jetbrains.annotations.Nullable;

import java.lang.reflect.Field;

/**
 * Helps to specify the type of the variables of an enum
 */
public interface TypedEnum<T extends java.lang.Enum<T> & TypedEnum<T, V> & Enum<T>, V> {

}
