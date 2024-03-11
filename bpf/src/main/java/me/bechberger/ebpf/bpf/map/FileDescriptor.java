package me.bechberger.ebpf.bpf.map;

/**
 * File descriptor, used to identify a map
 */
public record FileDescriptor(String name, int fd) {
}
