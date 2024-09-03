Hello eBPF
==========

This is a modified version of [hello-ebpf](https://github.com/parttimenerd/hello-ebpf)
to support writing basic schedulers directly in Java
by implementing the `Scheduler` interface. But I do not plan to maintain this branch.

The main usage is my talk at the [eBPF Summit 2024](https://ebpf.io/summit-2024/):

> Keynote: Writing a Linux scheduler in Java with eBPF
>
> Sched_ext allows you to write a Linux scheduler with eBPF. Now that it finally comes to the mainline kernel, we want to make it accessible to a new group of people: Java developers. With our prototypical hello-ebpf library, it's now possible to write Linux schedulers and more using Java.
>
> Join me in learning about sched_ext and how to write a basic scheduler implementation in "pure" Java.

To run the [SampleScheduler](bpf-samples/src/main/java/me/bechberger/ebpf/samples/SampleScheduler.java), 
based on the simple scheduler from [sched-ext/scx](https://github.com/sched-ext/scx/blob/main/scheds/c/scx_simple.c),
first install [CachyOS](https://cachyos.org) and all the [required libraries to build scx](https://github.com/sched-ext/scx).

Then you can build the SampleScheduler with:

```shell
./build.sh
```

And run it with in a shell with root privileges  (`sudo -s PATH=$PATH`):

```shell
./run.sh SampleScheduler
```

If everything went well, you should see the output of the scheduler in the console, something like

```shell
PID        Process Name         Enqueue Count
---------------------------------------------
2487       glean.dispatche           97088
2608       WRRende~ckend#1           36183
2606       WRScene~ilder#1           26845
2607       WRScene~derLP#1           11533
224271     StyleThread#3              1544
224270     StyleThread#2              1347
```

Sched-ext is not (yet) a part of the mainline kernel, so don't expect everything to work out of the box.

Visit the main repository to learn more about [hello-ebpf](https://github.com/parttimenerd/hello-ebpf).

License
-------
Apache 2.0, Copyright 2023 SAP SE or an SAP affiliate company, Johannes Bechberger and contributors.
The Scheduler interface and the SampleScheduler are licensed under the GPL 2.0 license.