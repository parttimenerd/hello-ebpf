Hello eBPF
==========

There are [user land libraries](https://ebpf.io/what-is-ebpf/#development-toolchains) for eBPF that allow you to
write eBPF applications in Python C++, Rust, Go, Python and even
Lua. But there are none for Java, which is a pitty.
So... I decided to write bindings, using [Project Panama](https://openjdk.org/projects/panama/)
and [bcc](https://github.com/isovalent/bcc), the first, and widely used, user land library for eBPF. 
bcc is mainly used with its Python bindings.

Support for [libbpf](https://github.com/libbpf/libbpf) is planned...

Hello eBPF world!
-----------------

Hello Java world! Let's discover eBPF together, join me on the journey to write
all examples from the [Learning eBPF book](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)
(get it also from [Bookshop.org](https://bookshop.org/p/books/learning-ebpf-programming-the-linux-kernel-for-enhanced-observability-networking-and-security-liz-rice/19244244?ean=9781098135126),
[Amazon](https://www.amazon.com/Learning-eBPF-Programming-Observability-Networking/dp/1098135121), or [O'Reilly](https://www.oreilly.com/library/view/learning-ebpf/9781098135119/)), by
Liz Rice in Java, implementing a Java user land library for eBPF along the way.

This project is still in its early stages
and a read-along of the book is recommended:

__We're currently at page 18 of the book.__

Goals
-----
Provide a library (and documentation) for Java developers to explore eBPF and
write their own eBPF programs, and the [examples](https://github.com/lizrice/learning-ebpf) from the [book](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf) without having to Python.

The initial goal is to be as close to bcc Python API as possible, so that the examples from the book
can be ported to Java easily.

You can find the Java versions of the examples in the [src/main/me/bechberger/samples](src/main/me/bechberger/samples)
and the API in the [src/main/me/bechberger/bcc](src/main/me/bechberger/bcc) directory.

Prerequisites
-------------

These might change in the future, but for now you need the following:

Either a Linux machine with the following:

- Linux x64 (or in a VM)
- Java 21 (exactly this version, as we need [Project Panama](https://openjdk.org/projects/panama/) with is a preview
  feature), we'll switch to Java 22 as soon as it is released
- Python 3.8 (or newer, for the binding generator
- clang (for [jextract](https://github.com/openjdk/jextract) to generate the bindings)
- libbcc (see [bcc installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md), be sure to install the libbpfcc-dev package)
- root privileges (for eBPF programs)
- Maven 3.6.3 (or newer, to build the project)

On Mac OS you can use the Lima VM (or use `hello-ebpf.yaml` file as a guide to install the prerequisites):

```sh
limactl start hello-ebpf.yaml
limactl shell hello-ebpf

# You'll need to be root for most of the examples
sudo -s
```

There are only jextract builds for x86_64, therefore arm64 is not supported at the moment.

*This is an area where you can contribute, if you can. Being able to build this project
on arm64 without running in QEMU would certainly be helpful.*

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
> ./run.sh bcc.HelloWorld
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

- Dec 01, 2023: [Finding all used Classes, Methods and Functions of a Python Module](https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/)
- Dec 11, 2023: [From C to Java Code using Panama](https://mostlynerdless.de/blog/2023/12/11/from-c-to-java-code-using-panama/)

Planned:

- Hello eBPF: Developing eBPF Apps in Java (Part 1)

Examples
--------

We implement the Java API alongside implementing the examples from the book, so we track the progress
of the implementation by the examples we have implemented. We also use examples from different sources
like the bcc repository and state this in the first column.


| Chapter<br/>/Source | Example                                    | Java class                                                                               | Status | Description                                    |
|---------------------|--------------------------------------------|------------------------------------------------------------------------------------------|--------|------------------------------------------------|
| bcc                 | [hello_world.py](pysamples/hello_world.py) | [HelloWorld](src/main/java/me/bechberger/ebpf/samples/bcc/HelloWorld.java)               | works  | Basic hello world                              |
| 2                   | [2_hello.py](pysamples/2_hello.py)         | [chapter2.HelloWorld](src/main/java/me/bechberger/ebpf/samples/chapter2/HelloWorld.java) | works  | print "Hello World!" for each `execve` syscall |


... more to come from the [books' repository](https://github.com/lizrice/learning-ebpf/tree/main)


Classes
-------
All classes and methods have the name as in the Python API, introducing things like builders only
for more complex cases (like the constructor of `BPF`).

The comments for all of these entities are copied from the Python API and extended where necessary.

Plans
-----

A look ahead into the future, so you know what to expect:

- Implement the API so that we can recreate all bcc examples from the book
- Make it properly available as a library on Maven Central
- Support the newer [libbpf](https://github.com/libbpf/libbpf) library
- Allow writing eBPF programs in Java

These plans might change, but I'll try to keep this up to date.
I'm open for suggestions, contributions and ideas.

Contributing
------------
Contributions are welcome, just open an 
[issue](https://github.com/parttimenerd/hello-ebpf/issues/new) or a 
[pull request](https://github.com/parttimenerd/hello-ebpf/pulls).
Discussions take place in the [discussions](https://github.com/parttimenerd/hello-ebpf/discussions)
section of the GitHub repository.

I'm happy to include more example programs, API documentation or helper methods,
as well as links to repositories and projects that use this library.

License
-------
Apache 2.0, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors

_This is a side project. The amount of time that I'm able to invest might vary over time._