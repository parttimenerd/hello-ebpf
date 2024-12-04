Hello eBPF
==========

There are [user land libraries](https://ebpf.io/what-is-ebpf/#development-toolchains) for [eBPF](https://ebpf.io) that allow you to
write eBPF applications in C++, Rust, Go, Python and even
Lua. But there are none for Java, which is a pity.
So... I decided to write my own, which allows you to write
eBPF programs directly in Java.

This is still in the early stages, but you can already use it for developing small tools
and more coming in the future.

![Overview images](img/overview.svg)

_Based on the overview from [ebpf.io](https://ebpf.io/what-is-ebpf/), 
duke image from [OpenJDK](https://wiki.openjdk.org/display/duke/Gallery)._

Let's discover eBPF together. Join me on the journey and learn a lot about eBPF and Java along the way.

Example
-------
Consider for a brief moment that you want to test how your server application behaves when every third incoming
network packet is dropped. We can write a simple eBPF program to do this:

```java
@BPF(license = "GPL")
public abstract class XDPDropEveryThirdPacket extends BPFProgram implements XDPHook {

  final GlobalVariable<@Unsigned Integer> count = new GlobalVariable<>(0);

  @BPFFunction
  public boolean shouldDrop() {
    return count.get() % 3 == 1;
  }

  @Override // runs directly in the kernel on every incoming packet
  public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
    // this code is actually compiled to the C code that is executed in the kernel
    count.set(count.get() + 1);
    return shouldDrop() ? xdp_action.XDP_DROP : xdp_action.XDP_PASS;
  }

  // runs in user land
  public static void main(String[] args) throws InterruptedException {
    try (XDPDropEveryThirdPacket program = BPFProgram.load(XDPDropEveryThirdPacket.class)) {
      // attach the xdpHandlePacket method to the network interface
      program.xdpAttach(XDPUtil.getNetworkInterfaceIndex());
      // print the current packet count in a loop
      while (true) {
        System.out.println("Packet count " + program.count.get());
        Thread.sleep(1000);
      }
    }
  }
}
```

You can find this example as [XDPDropEveryThirdPacket.java](bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java).

Goals
-----
Provide a library (and documentation) for Java developers to explore eBPF and
write their own eBPF programs, like firewalls, directly in Java, using the [libbpf](https://libbpf.readthedocs.io/en/latest/)
under the hood.

The goal is neither to replace existing eBPF libraries nor to provide a higher abstractions.

Prerequisites
-------------

These might change in the future, but for now, you need the following:

Either a Linux machine with the following:

- Linux 64-bit (or a VM)
- Java 22 or later
- libbpf and bpf-tool
  - e.g. `apt install libbpf-dev linux-tools-common linux-tools-$(uname -r)` on Ubuntu
- root privileges (for executing the eBPF programs)

- On Mac OS, you can use the [Lima VM](https://lima-vm.io/) (or use the `hello-ebpf.yaml` file as a guide to install the prerequisites):

```sh
limactl start hello-ebpf.yaml --mount-writable
limactl shell hello-ebpf sudo bin/install.sh
limactl shell hello-ebpf

# You'll need to be root for most of the examples
sudo -s PATH=$PATH
```

The scheduler examples require a patched 6.11 kernel with the scheduler extensions, you can get it from 
[here](https://launchpad.net/~arighi/+archive/ubuntu/sched-ext-unstable).
You might also be able to run [CachyOS](https://cachyos.org/) and install a patched kernel from there.

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
- Jul 02, 2024: [Hello eBPF: BPF Type Format and 13 Thousand Generated Java Classes (11)](https://mostlynerdless.de/blog/2024/07/02/hello-ebpf-bpf-type-format-and-13-thousand-generated-java-classes-11/)
- Jul 30, 2024: [Hello eBPF: Write your eBPF application in Pure Java (12)](https://mostlynerdless.de/blog/2024/07/30/hello-ebpf-write-your-ebpf-application-in-pure-java-12/)
- Aug 13, 2024: [Hello eBPF: A Packet Logger in Pure Java using TC and XDP Hooks (13)](https://mostlynerdless.de/blog/2024/08/13/hello-ebpf-a-packet-logger-in-pure-java-using-tc-and-xdp-hooks-13/)
- Aug 27, 2024: [Hello eBPF: Building a Lightning Fast Firewall with Java & eBPF (14)](https://mostlynerdless.de/blog/2024/08/27/hello-ebpf-building-a-lightning-fast-firewall-with-java-ebpf-14/)
- Sep 10, 2024: [Hello eBPF: Collection of Resources for eBPF (14.5)](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-collection-of-resources-for-ebpf-14-5/)
- Sep 10, 2024: [Hello eBPF: Writing a Linux scheduler in Java with eBPF (15)](https://mostlynerdless.de/blog/2024/09/10/hello-ebpf-writing-a-linux-scheduler-in-java-with-ebpf-15/)
- Dec 03, 2024: [Hello eBPF: Control task scheduling with a custom scheduler written in Java (16)](https://mostlynerdless.de/blog/2024/12/03/hello-ebpf-control-task-scheduling-with-a-custom-scheduler-written-in-java-16/)

Examples
--------

I wrote a few samples that showcase the usage of the library in the [bpf-samples](bpf-samples) module,
you can use them as a starting point for your own eBPF programs.

| Inspiration | Name and Java Class                                                                                                        | Description                                                                |
|-------------|----------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
|             | [HelloWorld](bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloWorld.java)                                         | A simple hello world example                                               |
|             | [LogOpenAt2Call](bpf-samples/src/main/java/me/bechberger/ebpf/samples/LogOpenAt2Calls.java)                                | Logs all openat2 calls                                                     |
| Ansil H     | [RingSample](bpf-samples/src/main/java/me/bechberger/ebpf/samples/RingSample.java)                                         | Record openat2 calls in a ring buffer                                      |
|             | [HashMapSample](bpf-samples/src/main/java/me/bechberger/ebpf/samples/HashMapSample.java)                                   | Record openat2 calls in a hash map                                         |
|             | [XDPDropEveryThirdPacket](bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPDropEveryThirdPacket.java)               | Use XDP to block every third incoming packet                               |
| sematext    | [XDPPacketFilter](bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPPacketFilter.java)                               | Use XDP to block incoming packages from specific URLs in Java              |
| sematext    | [XDPPacketFilter2](bpf-samples/src/main/java/me/bechberger/ebpf/samples/XDPPacketFilter2.java)                             | The previous example but with the eBPF program as C code                   |
|             | [TCDropEveryThirdOutgoingPacket](bpf-samples/src/main/java/me/bechberger/ebpf/samples/TCDropEveryThirdOutgoingPacket.java) | Implement a Traffic Control to block every third outgoing packet at random |
|             | [PacketLogger](bpf-samples/src/main/java/me/bechberger/ebpf/samples/PacketLogger.java)                                     | TC and XDP based packet logger, capturing incoming and outgoing packets    |
| nfil.dev    | [CGroupBlockHTTPEgress](bpf-samples/src/main/java/me/bechberger/ebpf/samples/CGroupBlockHTTPEgress.java)                   | Block all outgoing HTTP packets using cgroups                              |
|             | [demo.ForbiddenFile](bpf-samples/src/main/java/me/bechberger/ebpf/samples/demo/ForbiddenFile.java)                         | Block access to a specific file via openat2                                |
|             | [Firewall](bpf-samples/src/main/java/me/bechberger/ebpf/samples/Firewall.java)                                             | A simple firewall that blocks all incoming packets                         |
|             | [FirewallSpring](bpf-samples/src/main/java/me/bechberger/ebpf/samples/FirewallSpring.java)                                 | A spring boot based web front-end for the Firewall                         |
|             | [MinimalScheduler](bpf-samples/src/main/java/me/bechberger/ebpf/samples/MinimalScheduler.java)                             | A minimal Linux scheduler                                                  | 

Running the Examples
--------------------
Be sure to run the following in a shell with root privileges that uses JDK 22:

```shell
# in the project directory
./run.sh EXAMPLE_NAME

# list all examples
./run.sh
```

This allows you to easily run the example from above:

```
> ./build.sh
>  ./run.sh XDPDropEveryThirdPacket
Packet count 0
Packet count 2
Packet count 3
Packet count 5
Packet count 6
Packet count 8
Packet count 9
Packet count 11
```

You can use the `debug.sh` to run an example with a debugger port open at port 5005.

Build
-----
To build the project, make sure you have all prerequisites installed, then just run:

```shell
./build.sh
```

Usage as a library
------------------
The library is available as a maven package:

```xml
<dependency>
    <groupId>me.bechberger</groupId>
    <artifactId>bpf</artifactId>
    <version>0.1.1-scx-enabled-SNAPSHOT</version>
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

<details>
<summary>You have to copy the .mvn/jvm.config file and add the annotation processor to your project.</summary>
To properly use hello-ebpf as a library, you have to allow the maven compiler to access all the required internal
APIs. You can do this by copying the `.mvn/jvm.config` file from this repository to your project.

Furthermore, you have to add the annotation processor to your project:

```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-compiler-plugin</artifactId>
  <version>3.8.0</version>
  <configuration>
    <annotationProcessors>
      <annotationProcessor>me.bechberger.ebpf.bpf.processor.Processor</annotationProcessor>
    </annotationProcessors>
    <compilerArgs>
      <arg>-Xplugin:BPFCompilerPlugin</arg>
    </compilerArgs>
  </configuration>
</plugin>
```

</details>

Plans
-----

A look ahead into the future, so you know what to expect:

- Implement more features related to libbpf and eBPF
  - cgroups support
- More documentation
- Support for macros

These plans might change, but I'll try to keep this up to date.
I'm open to suggestions, contributions, and ideas.

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