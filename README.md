Hello eBPF
==========

There are Python bindings, but not Java bindings for
[bcc](https://github.com/isovalent/bcc) to work with eBPF.
So... I decided to write bindings, using[Project Panama](https://openjdk.org/projects/panama/).

Hello eBPF world! Hello Java world! Let's discover eBPF together, join me on the journey to write
all examples from the [Learning eBPF book](https://learning.oreilly.com/library/view/learning-ebpf/9781492050177/) by
Liz Rice in Java, implementing the Java API for bcc along the way.

This project is still in its early stages, so stay tuned.

*We're currently at page 18 of the book.*

Goals
-----
Provide a library (and documentation) for Java developers to explore eBPF and
write their own eBPF programs, and the examples from the book without having to Python.

The library should be as close to the Python API as possible, so that the examples from the book
can be ported to Java easily.

You can find the Java versions of the examples in the [src/main/me/bechberger/samples](src/main/me/bechberger/samples)
and the API in the [src/main/me/bechberger/bcc](src/main/me/bechberger/bcc) directory.

Prerequisites
-------------

- Linux x86_64 (or in a VM)
- Java 21 (exactly this version, as we need [Project Panama](https://openjdk.org/projects/panama/) with is a preview
  feature)
- Python 3.8 (or newer)
- clang (for jextract)
- libbcc (see [bcc installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md))
- root privileges (for eBPF programs)
- Maven 3.6.3 (or newer, to build the project)

Build
-----
To build the project, make sure you have all prerequisites installed and run:

```shell
mvn clean package
```

Running the examples
--------------------
Be sure to run the following in a shell with root privileges that uses JDK 21:

```shell
java --enable-preview -cp target/bcc.jar --enable-native-access=ALL-UNNAMED me.bechberger.ebpf.samples.EXAMPLE_NAME
# or
./run.sh EXAMPLE_NAME
```

The following runs the hello world sample from the vcc repository. It currently prints something like:

```
> ./run.sh HelloWorld
           <...>-30325   [042] ...21 10571.161861: bpf_trace_printk: Hello, World!\n
             zsh-30325   [004] ...21 10571.164091: bpf_trace_printk: Hello, World!\n
             zsh-30325   [115] ...21 10571.166249: bpf_trace_printk: Hello, World!\n
             zsh-39907   [127] ...21 10571.167210: bpf_trace_printk: Hello, World!\n
             zsh-30325   [115] ...21 10572.231333: bpf_trace_printk: Hello, World!\n
             zsh-30325   [060] ...21 10572.233574: bpf_trace_printk: Hello, World!\n
             zsh-30325   [099] ...21 10572.235698: bpf_trace_printk: Hello, World!\n
             zsh-39911   [100] ...21 10572.236664: bpf_trace_printk: Hello, World!\n
 MediaSu~isor #3-19365   [064] ...21 10573.417254: bpf_trace_printk: Hello, World!\n
 MediaSu~isor #3-22497   [000] ...21 10573.417254: bpf_trace_printk: Hello, World!\n
 MediaPD~oder #1-39914   [083] ...21 10573.418197: bpf_trace_printk: Hello, World!\n
 MediaSu~isor #3-39913   [116] ...21 10573.418249: bpf_trace_printk: Hello, World!\n
```

The related code is:

```java
public class HelloWorld {
    public static void main(String[] args) {
        try (BPF b = BPF.builder("""
                int kprobe__sys_clone(void *ctx) {
                   bpf_trace_printk("Hello, World!\\\\n");
                   return 0;
                }
                """).build()) {
            b.trace_print();
        }
    }
}
```

You can use the `debug.sh` to run an example with a debugger port open at port 5005.

Blog Posts
----------
Posts covering the development of this project:

- Dec 1, 2023: [Finding all used Classes, Methods and Functions of a Python Module](https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/)

Planned:

- Using jextract to generate the Java API for bcc
- Getting the errno for C calls with Panama
- Hello eBPF: Running a hello world eBPF program from Java
- Creating an interruptible BufferReader in Java

Examples
--------

We implement the Java API alongside implementing the examples from the book, so we track the progress
of the implementation by the examples we have implemented. We also use examples from different sources
like the bcc repository and state this in the first column.

| Chapter<br/>/Source | Example | Java class | Status | Description |
|---------------------|-------------------------------------------|-------------|------------------------------------------------|
| bcc | [hello_world.py](pysamples/hello_world.py) | HelloWorld | works | print "Hello World!" for each `clone`
syscall |
| 2 | [2_hello.py](pysamples/2_hello.py) | chapter2.HelloWorld | works | print "Hello World!" for each `execve`
syscall |
... more to come from the [books' repository](https://github.com/lizrice/learning-ebpf/tree/main)


Classes
-------
All classes and methods have the name as in the Python API, introducing things like builders only
for more complex cases (like the constructor of `BPF`).

The comments for all of these entities are copied from the Python API and extended where necessary.

License
-------
Apache 2.0