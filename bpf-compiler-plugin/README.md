BPF Java Compiler Plugin
========================

A plugin for the Java compiler that lets you write the C implementation of BPF functions in Java.
It runs in conjunction with [bpf-processor](../bpf-processor) to compile the C code to BPF bytecode.

This is in its earliest stages of experimentation.

## Concept

Write something like

```java
@BuiltinBPFFunction
public int abs(int a, int b) {
    throw new BuiltinBPFFunction();
}

@BPFFunction
public int myBPFFunction(int a, int b) {
    return abs(a - b);
}
```

and the plugin will generate the following C code:

```c
int myBPFFunction(int a, int b) {
    return abs(a - b);
}
```

## Requirements

- clang
- libbpf
- bpftool

Or on Ubuntu or Debian:
```sh
    sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
```