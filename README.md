Hello eBPF
==========

<!--[![Early Access](https://github.com/parttimenerd/hello-ebpf/actions/workflows/early-access.yml/badge.svg)](https://github.com/parttimenerd/hello-ebpf/actions/workflows/early-access.yml)-->

There are [user land libraries](https://ebpf.io/what-is-ebpf/#development-toolchains) for [eBPF](https://ebpf.io) that allow you to
write eBPF applications in C++, Rust, Go, Python and even
Lua. But there are none for Java, which is a pity.
So... I decided to write bindings using [Project Panama](https://openjdk.org/projects/panama/)
and [bcc](https://github.com/iovisor/bcc), the first and widely used userland library for eBPF,
which is typically used with its Python API.
_Work is on the way to work on the [libbpf](https://www.kernel.org/doc/html/latest/bpf/libbpf/libbpf_overview.html)
support in the [bpf](bpf) and [bpf-processor](bpf-processor) modules._

![Overview images](img/overview.svg)

_Based on the overview from [ebpf.io](https://ebpf.io/what-is-ebpf/), 
duke image from [OpenJDK](https://wiki.openjdk.org/display/duke/Gallery)._

Hello eBPF world! Hello Java world!
-----------------

Let's discover eBPF together. Join me on the journey to write
all examples from the [Learning eBPF book](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)
(get it also from [Bookshop.org](https://bookshop.org/p/books/learning-ebpf-programming-the-linux-kernel-for-enhanced-observability-networking-and-security-liz-rice/19244244?ean=9781098135126),
[Amazon](https://www.amazon.com/Learning-eBPF-Programming-Observability-Networking/dp/1098135121), or [O'Reilly](https://www.oreilly.com/library/view/learning-ebpf/9781098135119/)), by
Liz Rice in Java, implementing a Java userland library for eBPF along the way,
with a [blog series](https://mostlynerdless.de/blog/tag/hello-ebpf/) to document the journey.

This project is still in its early stages, and a read-along of the book is recommended:

__We're currently at page 23 of the book in the [blog series](https://mostlynerdless.de/blog/tag/hello-ebpf/)
and page 36 with this repo.__

It is evolving fast, you can already implement all examples and exercises from chapter 2.

A sample project using the library can be found in the [sample-bcc-project](https://github.com/parttimenerd/sample-bcc-project)
repository.

Goals
-----
Provide a library (and documentation) for Java developers to explore eBPF and
write their own eBPF programs, and the [examples](https://github.com/lizrice/learning-ebpf) from the [book](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf) without having to Python.

The initial goal is to be as close to bcc Python API as possible so that the examples from the book
can be ported to Java easily.

You can find the Java versions of the examples in the [bcc/src/main/me/bechberger/samples](bcc/src/main/me/bechberger/samples)
and the API in the [bcc/src/main/me/bechberger/bcc](bcc/src/main/me/bechberger/bcc) directory.

Prerequisites
-------------

These might change in the future, but for now, you need the following:

Either a Linux machine with the following:

- Linux 64-bit (or a VM)
- Java 22 or later
- libbcc (see [bcc installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md), be sure to install the libbpfcc-dev package)
  - e.g. `apt install bpfcc-tools libbpfcc-dev linux-tools-common linux-tools-$(uname -r)` on Ubuntu
- root privileges (for eBPF programs)
On Mac OS, you can use the [Lima VM](https://lima-vm.io/) (or use the `hello-ebpf.yaml` file as a guide to install the prerequisites):

```sh
limactl start hello-ebpf.yaml --mount-writable
limactl shell hello-ebpf sudo bin/install.sh
limactl shell hello-ebpf

# You'll need to be root for most of the examples
sudo -s PATH=$PATH
```

Build
-----
To build the project, make sure you have all prerequisites installed, then just run:

```shell
./build.sh
```

Running the examples
--------------------
Be sure to run the following in a shell with root privileges that uses JDK 22:

```shell
java -cp bcc/target/bcc.jar --enable-native-access=ALL-UNNAMED me.bechberger.ebpf.samples.EXAMPLE_NAME
# or in the project directory
./run.sh EXAMPLE_NAME

# list all examples
./run.sh
```

The following runs the hello world sample from the vcc repository. It currently prints something like:

```
> ./run.sh bcc.HelloWorld
           <...>-30325   [042] ...21 10571.161861: bpf_trace_printk: Hello, World!
             zsh-30325   [004] ...21 10571.164091: bpf_trace_printk: Hello, World!
             zsh-30325   [115] ...21 10571.166249: bpf_trace_printk: Hello, World!
             zsh-39907   [127] ...21 10571.167210: bpf_trace_printk: Hello, World!
             zsh-30325   [115] ...21 10572.231333: bpf_trace_printk: Hello, World!
             zsh-30325   [060] ...21 10572.233574: bpf_trace_printk: Hello, World!
             zsh-30325   [099] ...21 10572.235698: bpf_trace_printk: Hello, World!
             zsh-39911   [100] ...21 10572.236664: bpf_trace_printk: Hello, World!
 MediaSu~isor #3-19365   [064] ...21 10573.417254: bpf_trace_printk: Hello, World!
 MediaSu~isor #3-22497   [000] ...21 10573.417254: bpf_trace_printk: Hello, World!
 MediaPD~oder #1-39914   [083] ...21 10573.418197: bpf_trace_printk: Hello, World!
 MediaSu~isor #3-39913   [116] ...21 10573.418249: bpf_trace_printk: Hello, World!
```

The related code is ([chapter2/HelloWorld.java](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloWorld.java)):

```java
public class HelloWorld {
  public static void main(String[] args) {
    try (BPF b = BPF.builder("""
            int hello(void *ctx) {
               bpf_trace_printk("Hello, World!");
               return 0;
            }
            """).build()) {
      var syscall = b.get_syscall_fnname("execve");
      b.attach_kprobe(syscall, "hello");
      b.trace_print();
    }
  }
}
```

Which is equivalent to the Python [code](pysamples/chapter2/hello.py) and prints "Hello, World!" for each `execve` syscall:

```python
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
```

You can use the `debug.sh` to run an example with a debugger port open at port 5005.

Usage as a library
------------------
The library is available as a Maven package:

```xml
<dependency>
    <groupId>me.bechberger</groupId>
    <artifactId>bcc</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

You might have to add the https://s01.oss.sonatype.org/content/repositories/releases/ repo:
```xml
<repositories>
    <repository>
        <id>snapshots</id>
        <url>https://s01.oss.sonatype.org/content/repositories/snapshots/</url>
        <releases>
            <enabled>false</enabled>
        </releases>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>
```

Blog Posts
----------
Posts covering the development of this project:

- Dec 01, 2023: [Finding all used Classes, Methods, and Functions of a Python Module](https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/)
- Dec 11, 2023: [From C to Java Code using Panama](https://mostlynerdless.de/blog/2023/12/11/from-c-to-java-code-using-panama/)
- Jan 01, 2024: [Hello eBPF: Developing eBPF Apps in Java (1)](https://mostlynerdless.de/blog/2023/12/31/hello-ebpf-developing-ebpf-apps-in-java-1/)
- Jan 12, 2024: [Hello eBPF: Recording data in basic eBPF maps (2)](https://mostlynerdless.de/blog/2024/01/12/hello-ebpf-recording-data-in-basic-ebpf-maps-2/)
- Jan 29, 2024: [Hello eBPF: Recording data in perf event buffers (3)](https://mostlynerdless.de/blog/2024/01/29/hello-ebpf-recording-data-in-event-buffers-3/)
- Feb 12, 2024: [Hello eBPF: Tail calls and your first eBPF application (4)](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/)
- Feb 26, 2024: [Hello eBPF: First steps with libbpf (5)](https://mostlynerdless.de/blog/2024/02/26/hello-ebpf-first-steps-with-libbpf-5/)
- Mar 12, 2024: [Hello eBPF: Ring buffers in libbpf (6)](https://mostlynerdless.de/blog/2024/03/12/hello-ebpf-ring-buffers-in-libbpf-6/)
- Mar 22, 2024: [Hello eBPF: Auto Layouting Structs (7)](https://mostlynerdless.de/blog/2024/03/22/hello-ebpf-auto-layouting-structs-7/)
- Apr 09, 2024: [Hello eBPF: Generating C Code (8)](https://mostlynerdless.de/blog/2024/04/09/hello-ebpf-generating-c-code-8/)
- Apr 22, 2024: [Hello eBPF: XDP-based Packet Filter (9)](https://mostlynerdless.de/blog/2024/04/22/hello-ebpf-xdp-based-packet-filter-9/)
- May 21, 2024: [Hello eBPF: Global Variables (10)](https://mostlynerdless.de/blog/2024/05/21/hello-ebpf-global-variables-10/)

Examples
--------

We implement the Java API alongside implementing the examples from the book, so we track the progress
of the implementation by the examples we have implemented. We also use examples from different sources
like the bcc repository and state this in the first column.


| Chapter<br/>/Source | Example                                                        | Java class                                                                                     | Status | Description                                                                            |
|---------------------|----------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------|----------------------------------------------------------------------------------------|
| bcc                 | [bcc/hello_world.py](pysamples/bcc/hello_world.py)             | [HelloWorld](bcc/src/main/java/me/bechberger/ebpf/samples/bcc/HelloWorld.java)                 | works  | Basic hello world                                                                      |
| 2                   | [chapter2/hello.py](pysamples/chapter2/hello.py)               | [chapter2.HelloWorld](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloWorld.java)   | works  | print "Hello World!" for each `execve` syscall                                         |
| 2                   | [chapter2/hello-map.py](pysamples/chapter2/hello-map.py)       | [chapter2.HelloMap](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloMap.java)       | works  | Count and print `execve` calls per user                                                |
| own                 | -                                                              | [own.HelloStructMap](bcc/src/main/java/me/bechberger/ebpf/samples/own/HelloStructMap.java)     | works  | Count and print `execve` calls per user and store the result as a struct in a map      |
| 2                   | [chapter2/hello-buffer.py](pysamples/chapter2/hello-buffer.py) | [chapter2.HelloBuffer](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloBuffer.java) | works  | Record information in perf buffer                                                      |
| 2                   | [chapter2/hello-tail.py](pysamples/chapter2/hello-tail.py)     | [chapter2.HelloTail](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/HelloTail.java)     | works  | Print a message when a syscall is called, and also when a timer is created or deleted. |
| 2                   | -                                                              | [chapter2.ex](bcc/src/main/java/me/bechberger/ebpf/samples/chapter2/ex)                        | works  | Implementation of some of the exercises for chapter 2                                  |
| own                 | [own/disassembler-test.py](pysamples/own/disassembler-test.py) | [own.DisassemblerTest](bcc/src/main/java/me/bechberger/ebpf/samples/own/DisassemblerTest.java) | works  | Disassemble byte-code for the HelloMap example                                         |


BPF Examples
------------
The examples from the book and other sources like [Ansil H's blog posts](https://ansilh.com/tags/ebpf/)
are implemented in the [bpf/src/main/me/bechberger/ebpf/samples](bpf/src/main/java/me/bechberger/ebpf/samples) directory.
You can run them using the `./run_bpf.sh` script. All examples have accompanying tests in the 
[bpf/src/test](bpf/src/test) directory.

| Source   | Java Class                                                                                     | Description                                           |
|----------|------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| Ansil H  | [HelloWorld](bpf/src/main/java/me/bechberger/ebpf/samples/Helloworld.java)                     | A simple hello world example                          |
| Ansil H  | [RingSample](bpf/src/main/java/me/bechberger/ebpf/samples/RingSample.java)                     | Record openat calls in a ring buffer                  |
|          | [TypeProcessingSample](bpf/src/main/java/me/bechberger/ebpf/samples/TypeProcessingSample.java) | RingSample using the @Type annotation                 |
|          | [HashMapSample](bpf/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java)               | Record openat calls in a hash map                     |
|          | [TypeProcessingSample](bpf/src/main/java/me/bechberger/ebpf/samples/TypeProcessingSample.java) | RingSample using more code generation                 |
| sematext | [XDPPacketFilter](bpf/src/main/java/me/bechberger/ebpf/samples/XDPPacketFilter.java)           | Use XDP to block incoming packages from specific URLs |

Classes and Methods
-------
All classes and methods have the name as in the Python API, introducing things like builders only
for more complex cases (like the constructor of `BPF`).

The comments for all of these entities are copied from the Python API and extended where necessary.

Plans
-----

A look ahead into the future so you know what to expect:

- Implement more features related to libbpf
  - cgroups support
- Allow writing eBPF programs in Java
- Drop libbcc and the BCC tools

These plans might change, but I'll try to keep this up to date.
I'm open to suggestions, contributions, and ideas.

Other modules
-------------
- [rawbcc](rawbcc/README.md): The raw BCC bindings generated by [jextract](https://github.com/openjdk/jextract)
- [rawbpf](rawbpf/README.md): The raw libbpf bindings


Testing
-------
Tests are run using [JUnit 5](https://junit.org/junit5/) and `./mvnw test`.
You can either run

```shell
./mvnw test -Dmaven.test.skip=false
```

or you can run the tests in a container using `testutil/bin/java`: 

```shell
./mvnw test -Djvm=testutil/bin/java -Dmaven.test.skip=false
```

This requires [virtme](https://github.com/ezequielgarcia/virtme) (`apt install virtme`), python 3, and docker to be installed.
You can run custom commands in the container using `testutil/run-in-container.sh`.
Read more in the [testutil/README.md](testutil/README.md).

I'm unable to get it running in the CI, so I'm currently running the tests locally.

Contributing
------------
Contributions are welcome; just open an 
[issue](https://github.com/parttimenerd/hello-ebpf/issues/new) or a 
[pull request](https://github.com/parttimenerd/hello-ebpf/pulls).
Discussions take place in the [discussions](https://github.com/parttimenerd/hello-ebpf/discussions)
section of the GitHub repository.

I'm happy to include more example programs, API documentation, or helper methods,
as well as links to repositories and projects that use this library.

License
-------
Apache 2.0, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors

_This is a side project. The amount of time I can invest might vary over time._