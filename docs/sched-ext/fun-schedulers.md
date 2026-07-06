# Fun Schedulers

sched_ext makes writing weird and creative schedulers surprisingly accessible. Here are
some schedulers built with hello-ebpf that show just how far you can take it.

---

## Sound Scheduler

Shout at your computer to make it run faster. The scheduler reads the microphone every
100 ms and scales the number of CPU cores allocated to your program with loudness. See
the [dedicated page](sound-scheduler.md) for the full write-up.

**Source:** [github.com/parttimenerd/loudness-scheduler](https://github.com/parttimenerd/loudness-scheduler)

---

## Taskclicker

> "Taskclicker lets you experience scheduling first hand, literally. It's a clicker-game
> scheduler GUI where you have to click on tasks to schedule them."

Taskclicker is a Linux CPU scheduler where **you are the scheduler.** A GUI shows you all
runnable tasks; you click on a task to dispatch it to a CPU. Earn virtual syscalls to buy
upgrades.

It implements first-come-first-served (FCFS) scheduling backed by hello-ebpf's sched_ext
support, submitted as an entry to the sched-ext-kit-contest.

**Source:** [github.com/Mr-Pine/taskclicker](https://github.com/Mr-Pine/taskclicker)

---

## Minimal Scheduler

The simplest possible scheduler that works: two methods, no extra DSQs, about 20 lines of
Java. A good starting point if you want to build something.

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
