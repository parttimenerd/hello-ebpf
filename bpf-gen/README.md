bpf-gen
=======

Generating Java type definitions for BTF files.

The generated classes are shipped with the [bpf-runtime](../bpf-runtime) artifact.

Background
----------
This tool uses the output of
```
bpftool btf dump file /sys/kernel/btf/vmlinux format raw -j 
```
to generate Java classes that represent the types defined in the BTF file.

For this it uses the generated JSON. The JSON format is used, as it's far
easier to work with JSON objects than with the raw binary data and libbpf.
But it is slower? Maybe, but emitting and parsing the JSON is done in less than
a second, so it's not a problem, the bottleneck is the creation of the Java code.

The JSON for `int` for example looks like this:
```json
{
  "bits_offset": 0,
  "size": 4,
  "kind": "INT",
  "name": "int",
  "id": 8,
  "encoding": "SIGNED",
  "nr_bits": 32
}
```

Build
-----
In parent folder

```shell
mvn -pl '!bpf' package
```

Run
---
It needs a lot of RAM, at least 16 GB, better 20 GB.

```shell
MAVEN_OPTS="-Xss1000m"
```

It produces around 3M lines of code, around 160MB of text.