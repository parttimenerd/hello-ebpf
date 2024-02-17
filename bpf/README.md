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
I'm creating a Java-esque API, not a mirror of a Python wrapper.

You can find the annotation processor in the [bpf-processor](../bpf-processor) module
and the library with examples in this module.

The mean idea with the annotation processor is that it transforms an example like 
[this](src/main/java/me/bechberger/ebpf/samples/Test.java) into something like this:

```java
public class Test {
    @BPF
    public static abstract class TestProgram extends BPFProgram {

        static final String EBPF_PROGRAM = """
                #include "vmlinux.h"
                #include <bpf/bpf_helpers.h>
                #include <bpf/bpf_tracing.h>
                            
                SEC ("kprobe/do_sys_openat2") int kprobe__do_sys_openat2 (struct pt_regs *ctx){                                                                   
                    bpf_printk("Hello, World from BPF and more!");
                    return 0;
                }
                char _license[] SEC ("license") = "GPL";
                """;
    }

    public static void main(String[] args) {
        try (TestProgram program = new TestProgramImpl()) {
            program.autoAttachProgram(program.getProgramByName("kprobe__do_sys_openat2"));
            program.tracePrintLoop();
        }
    }
}
```

Into the following, compiling in the eBPF byte-code in a sub-class `TestProgramImpl`
which already used above:
    
```java
package me.bechberger.ebpf.samples.tes

import me.bechberger.ebpf.samples.Test;

import java.util.Base64;

public final class TestProgramImpl extends Test.TestProgram {
    /**
     * Base64 encoded eBPF byte-code
     */
    private static final String BYTE_CODE =
            "f0VMRgIBAQAAAAAAAAAAAAEA9wABAA...QAAAAQAAAAIAAAAAAAAABgAAAAAAAAA";

    @Override
    public byte[] getByteCode() {
        return Base64.getDecoder().decode(BYTE_CODE);
    }
}
```

When you run the program via `./run_bpf.sh Test`, it will print something like the following:

```shell
      irqbalance-2003    [005] ...21 55240.855445: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855463: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855483: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855502: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855520: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855538: bpf_trace_printk: Hello, World from BPF and more!
      irqbalance-2003    [005] ...21 55240.855556: bpf_trace_printk: Hello, World from BPF and more!
           <...>-1773    [064] ...21 55240.869828: bpf_trace_printk: Hello, World from BPF and more!
 DefaultDispatch-178720  [094] ...21 55240.929322: bpf_trace_printk: Hello, World from BPF and more!
            code-4978    [086] ...21 55240.974095: bpf_trace_printk: Hello, World from BPF and more!
    systemd-oomd-1773    [064] ...21 55241.119825: bpf_trace_printk: Hello, World from BPF and more!
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

Build and run
-------------

In the main project directory:

```shell
./mvnw package
# run the example
./run_bpf.sh Test
```