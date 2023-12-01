PySamples
=========

Example Python code using the BCC Python bindings.
Taken from either the [bcc repository](https://github.com/iovisor/bcc/blob/master/examples/)
or the [Learning eBPF book](https://learning.oreilly.com/library/view/learning-ebpf/9781492050177/) by Liz Rice.

Sources are in the header of each file, all files are Apache 2.0 licensed if not stated otherwise.


Level of complexity
-------------------
1. hello_world.py: most basic hello world example
2. 2_hello.py: print "Hello World!" for each `execve` syscall