# Fun Schedulers

sched_ext makes writing weird and creative schedulers surprisingly accessible. Here are
some schedulers built with hello-ebpf that show just how far you can take it.

---

## Sound Scheduler

**Blog:** [Part 18 — A loudness-controlled CPU scheduler](https://mostlynerdless.de/blog/2025/03/23/hello-ebpf-a-cpu-scheduler-controlled-by-microphone-input-18/)  
**Talk:** [Chemnitz Linux Days 2025](https://speakerdeck.com/parttimenerd/write-your-own-cpu-scheduler-in-java)  
**Source:** [github.com/parttimenerd/loudness-scheduler](https://github.com/parttimenerd/loudness-scheduler)

Shout at your computer to make it run faster. The scheduler reads the microphone every
100 ms and scales the number of active CPU cores with loudness. Louder room → more cores
allocated; library quiet → CPU cores are throttled.

The idea came from Andrea Righi during [OSPM 2025](https://lpc.events/event/25/contributions/1960/).

### How it works

The BPF half is a FIFO scheduler with two `GlobalVariable` knobs the Java side updates
continuously:

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "loudness_scheduler")
public abstract class FIFOScheduler extends BPFProgram implements Scheduler {
    private static final int SHARED_DSQ_ID = 0;
    final GlobalVariable<Integer> cores = new GlobalVariable<>(
            Runtime.getRuntime().availableProcessors());
    final GlobalVariable<Integer> sliceNs = new GlobalVariable<>(-1);
```

`selectCPU` round-robins tasks across the active core count:

```java
@Override
public int selectCPU(Ptr<task_struct> p, int prev_cpu, long wake_flags) {
    if (!bpf_cpumask_full(p.val().cpus_ptr)) {
        return bpf_cpumask_first(p.val().cpus_ptr);
    }
    return (@Unsigned int) (prev_cpu + 1) % cores.get();
}
```

`enqueue` shrinks each task's slice proportionally to queue depth — louder input means more
cores, shorter per-task slice, higher throughput:

```java
@Override
public void enqueue(Ptr<task_struct> p, long enq_flags) {
    var slice = sliceNs.get() == -1 ? 5_000_000 : sliceNs.get();
    var scaledSlice = (@Unsigned int) slice /
            scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
    if (!bpf_cpumask_full(p.val().cpus_ptr)) {
        scx_bpf_dispatch(p, SCX_DSQ_LOCAL.value(), scaledSlice, 0);
        return;
    }
    scx_bpf_dispatch(p, SHARED_DSQ_ID, scaledSlice, enq_flags);
}
```

The Java main loop samples the microphone and pushes updated values every 100 ms:

```java
void schedule() {
    try (var program = BPFProgram.load(FIFOScheduler.class)) {
        program.attachScheduler();
        while (program.isSchedulerAttachedProperly()) {
            Thread.sleep(100);
            var loudness = sound.getLoudness();
            var frequencies = sound.getFrequencies();
            program.setCores(computeCores(loudness));
            if (frequency != -1) {
                program.setSlice((int) Math.round(
                    computeTimeSliceMillis(frequencies) * 1_000_000));
            }
        }
    }
}
```

### Bonus: frequency-controlled time slices

Pass `--frequency 440` to also scale each task's time slice by the dominant frequency in
the microphone input. Calibrate mode shows you what the scheduler sees:

```
> ./scheduler.sh --calibrate --frequency 440
Loudness:  0.0 -> cores:  1, top frequency:    -1 -> slice 147.0ms
Loudness:  7.0 -> cores:  8, top frequency:    23 -> slice 139.0ms
```

See the [dedicated page](sound-scheduler.md) for the full write-up and running instructions.

---

## Taskclicker

**Source:** [github.com/Mr-Pine/taskclicker](https://github.com/Mr-Pine/taskclicker)  
**Contest:** [sched-ext-kit-contest](https://github.com/parttimenerd/sched-ext-kit-contest)

Taskclicker is a Linux CPU scheduler where **you are the scheduler.** A GUI shows you all
runnable tasks; you click a task to dispatch it to a CPU.

> "Well… As I'm writing this, I'm not sure if this is what I was supposed to build when
> they tasked me with writing a fcfs scheduler for gaming with focus on interactivity… But
> well, it exists now, for better or for worse so have fun."
> — Mr-Pine, README

![Taskclicker screenshot: runnable task list, CPU slots, click to schedule](https://raw.githubusercontent.com/Mr-Pine/taskclicker/master/images/screenshot.png)

Can you keep your system fully interactive before the 30-second task timer runs out?
(Spoiler: the README was written with Taskclicker running.)

Written in Kotlin (69 %) + Java (31 %), it wires hello-ebpf's sched_ext support into a
desktop game. Build and run:

```bash
xhost si:localuser:root
sudo ./gradlew run
```

---

## Minimal Scheduler

The simplest scheduler that actually works: two methods, no extra DSQs, about 20 lines of
Java. A good starting point for your own experiments.

**Source:** [`MinimalScheduler.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/sched/MinimalScheduler.java)

```java
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_scheduler")
public abstract class MinimalScheduler extends SchedulerBase implements Scheduler {

    final DispatchQueue shared = DispatchQueue.attach(SHARED_DSQ_ID);

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        shared.insertScaled(p, EnqFlags.passThrough(enq_flags));
    }

    public static void main(String[] args) throws Exception {
        try (var program = BPFProgram.load(MinimalScheduler.class)) {
            program.runSchedulerLoop();
        }
    }
}
```

See [Writing a Scheduler](guide.md) to go from here to something more sophisticated.

---

## Lottery Scheduler

Assigns each task a random time slice drawn from a uniform distribution. Tasks with a
longer slice advance less in the virtual-time DSQ, producing a fair lottery among all
runnable tasks without per-task bookkeeping.

**Blog post:** [Part 17 — Writing a Lottery Scheduler in Java with sched_ext](https://mostlynerdless.de/blog/2024/12/17/hello-ebpf-writing-a-lottery-scheduler-in-java-with-sched-ext-17/)

![Lottery bowl: tasks enter, CPUs draw randomly](https://mostlynerdless.de/wp-content/uploads/2024/12/lottery_bowl.png)

---

## Your scheduler here?

If you build something interesting with hello-ebpf sched_ext support, open a PR or file
an issue to add it to this page.

---

*[Back to Overview](index.md)*
