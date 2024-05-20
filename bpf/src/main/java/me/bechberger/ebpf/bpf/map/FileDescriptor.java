package me.bechberger.ebpf.bpf.map;

import java.lang.foreign.MemorySegment;

/**
 * File descriptor, used to identify a map
 */
public record FileDescriptor(String name, MemorySegment map, int fd) {
}
