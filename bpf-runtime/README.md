BPF Runtime
================
[![Maven Central](https://img.shields.io/maven-central/v/me.bechberger/bpf-runtime)](https://search.maven.org/artifact/me.bechberger/bpf-runtime)

Definitions for Linux eBPF types and other helpers and interfaces,
generated from the Linux kernel sources by using [../bpf-gen](../bpf-gen).

These bindings are regularly updated and published on Maven Central:

```xml
<dependency>
    <groupId>me.bechberger</groupId>
    <artifactId>bpf-runtime</artifactId>
    <version>0.1.11-SNAPSHOT</version>
</dependency>
```

You might have to add the https://s01.oss.sonatype.org/content/repositories/snapshots/ repo:
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

Build
-----

This uses the bpf-gen tool to generate the Java classes.

Use `./build.sh` to build the project, but be aware that it needs a lot of RAM.
Run it with at least 20GB of RAM.

Release
-------

Run `./deploy.sh` after updating the version in the README and the pom.

License
-------
Apache 2.0, Copyright 2024 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors