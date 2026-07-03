# sched_ext — Callback Reference

## Scheduler callback reference

| Method | Required | Description |
|--------|----------|-------------|
| `enqueue(p, flags)` | **Yes** | Task becomes runnable; insert it into a DSQ |
| `dispatch(cpu, prev)` | **Yes** (if not using `SchedulerBase`) | CPU needs work; move tasks from DSQs to local |
| `init()` | No | Called once at load; create DSQs here |
| `exit(ei)` | No | Called when the scheduler is detached |
| `selectCPU(p, prev_cpu, wake_flags)` | No | Choose which CPU to wake for this task |
| `runnable(p, flags)` | No | Task became runnable (before `enqueue`) |
| `running(p)` | No | Task is about to execute on CPU |
| `stopping(p, runnable)` | No | Task left the CPU |
| `enable(p)` | No | Task entered SCX scheduling |
| `disable(p)` | No | Task left SCX scheduling |
| `tick(p)` | No | Periodic callback (every 1/HZ seconds) |
| `initTask(p, args)` | No | New task created; initialize per-task state |
| `exitTask(p, args)` | No | Task leaving the scheduler; free per-task state created in `initTask` |
| `dequeue(p, flags)` | No | Task removed from scheduler (e.g. priority change) |
| `runnable(p, flags)` | No | Task became runnable (counterpart to `quiescent`) |
| `quiescent(p, flags)` | No | Task became blocked/quiescent (counterpart to `runnable`) |
| `updateIdle(cpu, idle)` | No | CPU idle state changed |
| `cpuAcquire(cpu, args)` | No | CPU returned to SCX after preemption |
| `cpuRelease(cpu, args)` | No | CPU preempted by RT/deadline task; call `scx_bpf_reenqueue_local()` |
| `cpuOnline(cpu)` | No | CPU came online (hotplug) |
| `cpuOffline(cpu)` | No | CPU went offline (hotplug) |
| `yield(from, to)` | No | Task called `sched_yield()`; return `true` to honour, `false` to ignore |
| `setWeight(p, weight)` | No | Task scheduling weight changed (e.g. `setpriority(2)`) |
| `setCpumask(p, cpumask)` | No | Task CPU affinity changed (e.g. `sched_setaffinity(2)`) |
| `coreSchedBefore(a, b)` | No | Core scheduling priority: return `true` if `a` should run before `b` on a shared physical core |
| `dump(ctx)` | No | Global scheduler state dump (sched-ext debug interface) |
| `dumpCpu(ctx, cpu, idle)` | No | Per-CPU state dump |
| `dumpTask(ctx, p)` | No | Per-task state dump |

Cgroup-aware schedulers can also implement `cgroupInit`, `cgroupExit`, `cgroupPrepMove`,
`cgroupCancelMove`, `cgroupMove`, `cgroupSetWeight`, and `cgroupSetBandwidth`.

Callbacks are ordinary Java method overrides — no `@BPFFunction` needed.
The annotation processor generates all necessary BPF struct_ops wiring.
