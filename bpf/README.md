BPF
===

BCC is easy to use, but it has it's problems:
- it compiles the eBPF program at runtime
- having no pre-compilation means that the eBPF program is not checked for errors until it is loaded
- the user has to install the BCC tools and headers which includes LLVM
- the libbcc binaries on Ubuntu are outdated

So, I'm experimenting with using [libbpf](https://www.kernel.org/doc/html/next/bpf/libbpf/libbpf_overview.html),
compiling the eBPF program at in an annotation processor and using writing my own Java wrapper for libbpf.
This will remedy all the problems mentioned above.
The only caveat is that I have to start again. But this time,
I'm creating a well-tested Java-esque API, not a mirror of a Python wrapper.

You can find the annotation processor in the [bpf-processor](../bpf-processor) module
and the library with examples in this module.

The mean idea with the annotation processor is that it transforms an example like 
[this](src/main/java/me/bechberger/ebpf/samples/HelloWorld.java) into something like this:

```java
@BPF
public abstract class HelloWorld extends BPFProgram {

    static final String EBPF_PROGRAM = """
            #include "vmlinux.h"
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_tracing.h>
                            
            SEC ("kprobe/do_sys_openat2")
            int kprobe__do_sys_openat2(struct pt_regs *ctx){                                                             
                bpf_printk("Hello, World from BPF and more!");
                return 0;
            }
                            
            char _license[] SEC ("license") = "GPL";
            """;

    public static void main(String[] args) {
        try (HelloWorld program = BPFProgram.load(HelloWorld.class)) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            program.tracePrintLoop(f -> String.format("%d: %s: %s", (int)f.ts(), f.task(), f.msg()));
        }
    }
}
```

Into the following, compiling in the eBPF byte-code in a sub-class `HelloWorldImpl`:

```java
public final class HelloWorldImpl extends HelloWorld {
    /**
     * Base64 encoded gzipped eBPF byte-code
     */
    private static final String BYTE_CODE = "H4sIAA...n5q6hfQNFV+sgDAAA=";

    @Override
    public byte[] getByteCode() {
        return me.bechberger.ebpf.bpf.Util.decodeGzippedBase64(BYTE_CODE);
    }
}
```

When you run the program via `./run_bpf.sh HelloWorld`, it will print something like the following:

```shell
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: irqbalance: Hello, World from BPF and more!
3385: C2 CompilerThre: Hello, World from BPF and more!
```


**This is in its earliest stages of experimentation.**

## Requirements

- clang
- libbpf
- bpftool

Or on Ubuntu or Debian:
```sh
    sudo apt install clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

Or just use the lima VM in the parent directory.

Build and run
-------------

In the main project directory:

```shell
./mvnw package
# run the example
./run_bpf.sh HelloWorld
```

Test
----
Move to the parent directory.
On Linux (with virt-me and docker installed), run the tests with:
```shell
./mvnw test -Dmaven.test.skip=false -pl bpf -amd -Djvm=testutil/bin/java
```

In the lima VM, run the tests with:
```shell
sudo mvn test -Dmaven.test.skip=false -pl bpf -amd
```