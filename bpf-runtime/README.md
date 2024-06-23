Raw BPF Bindings
================
[![Maven Central](https://img.shields.io/maven-central/v/me.bechberger/rawbpf)](https://search.maven.org/artifact/me.bechberger/rawbpf)

Definitions for Linux eBPF types and other helpers and interfaces,
generated from the Linux kernel sources by using [../bpf-gen](../bpf-gen).

These bindings are regularly updated and published on Maven Central:

```xml
<dependency>
    <groupId>me.bechberger</groupId>
    <artifactId>bpf-runtime</artifactId>
    <version>0.1.0</version>
</dependency>
```

Requirements
------------
- Java 22
- Linux 64-bit
- btftool

Build
-----

This uses the bpf-gen tool to generate the Java classes.

Use `./build.sh` to build the project, but be aware that it needs a lot of RAM.
Run it with at least 20GB of RAM.

Release
-------

Run `./release.sh` after updating the version in the README and the pom.

License
-------
Apache 2.0, Copyright 2024 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors