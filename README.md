Hello eBPF
==========

There are Python bindings, but not Java bindings for 
[bcc](https://github.com/isovalent/bcc) to work with eBPF.
So... I decided to write bindings, using[Project Panama](https://openjdk.org/projects/panama/).

Hello eBPF world! Hello Java world! Let's discover eBPF together, join me on the journey to write
all examples from the [Learning eBPF book](https://learning.oreilly.com/library/view/learning-ebpf/9781492050177/) by Liz Rice in Java, implementing the Java API for bcc along the way.

This project is still in its early stages, so stay tuned.

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
- Java 21 (exactly this version, as we need [Project Panama](https://openjdk.org/projects/panama/) with is a preview feature)
- Python 3.8 (or newer)
- libbcc (see [bcc installation instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md))
- root privileges (for eBPF programs)
- Maven 3.6.3 (or newer, to build the project)

Build
-----
To build the project, make sure you have all prerequisites installed and run:
```shell
mvn clean package
```

Blog Posts
----------
Posts covering the development of this project:
- Dec 1, 2023: [Finding all used Classes, Methods and Functions of a Python Module](https://mostlynerdless.de/blog/2023/12/01/finding-all-used-classes-methods-and-functions-of-a-python-module/)


Examples
--------

We implement the Java API alongside implementing the examples from the book, so we track the progress
of the implementation by the examples we have implemented. We also use examples from different sources
like the bcc repository and state this in the first column.

| Chapter<br/>/Source | Example                                    | Status      | Description                                    |
|---------------------|--------------------------------------------|-------------|------------------------------------------------|
| bcc                 | [hello_world.py](pysamples/hello_world.py) | not started | most basic hello world example                 |
| 2                   | [2_hello.py](pysamples/2_hello.py)         | not started | print "Hello World!" for each `execve` syscall |
... more to come from the [books repository](https://github.com/lizrice/learning-ebpf/tree/main)


Classes
-------
Mapping of Python classes to Java classes.

License
-------
Apache 2.0