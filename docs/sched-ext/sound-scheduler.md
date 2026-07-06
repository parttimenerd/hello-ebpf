# Sound Scheduler

The sound scheduler is a CPU scheduler written in hello-ebpf that **controls how many
CPU cores your program uses based on ambient sound level.** Shout at your computer and
your application actually runs faster — the scheduler detects the loudness via the
microphone and scales core allocation proportionally.

This was demonstrated live at Chemnitz Linux Days 2025, where the audience participated
by shouting at a screen.

<iframe width="560" height="315" src="https://www.youtube.com/embed/ihAGd8GN90w" title="Sound of Scheduling — Writing Linux Schedulers in Java with eBPF" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

**Blog post:** [Part 20 — A Scheduler Controlled by Sound](https://mostlynerdless.de/blog/2025/03/25/hello-ebpf-a-scheduler-controlled-by-sound-20/)  
**Source:** [github.com/parttimenerd/loudness-scheduler](https://github.com/parttimenerd/loudness-scheduler)  
**Talk:** [Sound of Scheduling — Speakerdeck](https://speakerdeck.com/parttimenerd/sound-of-scheduling-writing-linux-schedulers-in-java-with-ebpf)

---

## How it works

The scheduler extends a simple FIFO kernelspace scheduler and adds two global BPF variables
that the Java main loop updates every 100 milliseconds:

- **`numCpus`** — how many cores tasks are allowed to use (scales with loudness 1–N)
- **`sliceNs`** — per-task time slice duration (also adjusted dynamically)

The `selectCPU` callback restricts usable cores to `numCpus` while still respecting
per-task CPU affinity constraints. The `enqueue` callback scales time slices inversely
with queue depth to stay responsive under load.

As a bonus, singing a note close to a configured frequency (e.g. 440 Hz) reduces the
time slice — frequency scaling as a scheduling knob.

```java
// The Java main loop polls the microphone every 100 ms
while (running) {
    double loudness = microphone.getRmsLevel();
    int cores = Math.max(1, (int)(loudness * availableCpus));
    prog.numCpus.set(cores);
    prog.sliceNs.set(computeSlice(cores));
    Thread.sleep(100);
}
```

The BPF side reads `numCpus` as a global variable — a zero-cost read from the kernel
because global variables are memory-mapped into the BPF program's address space.

---

## Why this is a good hello-ebpf demo

It shows all the pieces working together:

| Component | Role |
|-----------|------|
| `@BPF` class + `@BPFFunction` | The scheduler's BPF callbacks |
| `GlobalVariable<Integer>` | `numCpus` and `sliceNs` — written by Java, read in BPF |
| `SchedulerBase` + `DispatchQueue` | FIFO foundation |
| Java main loop | Polls microphone, updates globals |

The interesting part is not the scheduler algorithm — it's that the **scheduling policy
is controlled by a Java thread reading a microphone**, with changes taking effect in under
100 ms, all without a kernel patch.

---

## Running it

Clone and build the loudness-scheduler repository:

```bash
git clone https://github.com/parttimenerd/loudness-scheduler
cd loudness-scheduler
mvn package
sudo java -jar target/loudness-scheduler.jar
```

Requires a microphone (or any ALSA input device) and Linux ≥ 6.11 with sched_ext enabled.

---

*Next: [Fun Schedulers](fun-schedulers.md)*
