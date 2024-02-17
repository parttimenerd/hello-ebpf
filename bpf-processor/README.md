BPF Processor
=============

Annotation processor for processing BPF annotations and generating source code.

This is in it's earliest stages of experimentation.

## Requirements

- clang
- libbpf
- bpftool

Or on Ubuntu or Debian:
```sh
    sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
```