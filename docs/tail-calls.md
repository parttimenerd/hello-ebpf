# Tail calls in hello-ebpf

**Blog series:** [Part 4 — Tail calls and your first eBPF application](https://mostlynerdless.de/blog/2024/02/12/hello-ebpf-tail-calls-and-your-first-ebpf-application-4/)
**Javadoc:** [`BPFProgArray`](https://parttimenerd.github.io/hello-ebpf/javadoc/bpf/me/bechberger/ebpf/bpf/map/BPFProgArray.html)

![Stack frames with vs without a tail call — no stack growth with tail calls](https://mostlynerdless.de/wp-content/uploads/2024/02/tail_call-2000x599.png)

BPF programs cannot recurse or exceed the verifier's instruction budget, so
long dispatch chains are split into stages connected by **tail calls**:
`bpf_tail_call(ctx, &prog_array, slot)` transfers execution to the program
at `prog_array[slot]` and never returns. hello-ebpf gives you two surfaces
for this pattern:

1. **Raw `BPFProgArray`** — the primitive. `progs.register(slot, handle)`
   plus `progs.tailCall(ctx, slot)`. See
   [`TailCallDemo.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java).
2. **`@BPFTailCallTable`** — auto-registers slots from an enum. This page.

## `@BPFTailCallTable` in 60 seconds

```java
@BPF(license = "GPL")
public abstract class HelloTailCall extends BPFProgram implements XDPHook {

    public enum Slot { PARSE_ETH, PARSE_IP, COUNT }

    @BPFTailCallTable(slots = Slot.class)
    @BPFMapDefinition(maxEntries = 3)
    BPFProgArray dispatch;

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_ETH")
    public xdp_action parseEth(Ptr<xdp_md> ctx) { /* ... */ }

    @BPFFunction(section = "xdp")
    @TailCallSlot("PARSE_IP")
    public xdp_action parseIp(Ptr<xdp_md> ctx) { /* ... */ }

    @BPFFunction(section = "xdp")
    @TailCallSlot("COUNT")
    public xdp_action count(Ptr<xdp_md> ctx) { /* ... */ }
}
```

The annotation processor emits three lines into the generated
`HelloTailCallImpl` constructor, so `main()` needs no manual
`register(...)` calls:

```java
dispatch.register(0, getProgramByName("parseEth"));
dispatch.register(1, getProgramByName("parseIp"));
dispatch.register(2, getProgramByName("count"));
```

## Rules

- `maxEntries` on the sibling `@BPFMapDefinition` must equal the enum
  constant count.
- `@TailCallSlot("X")` — `X` must be the exact name of a constant of the
  target table's `slots()` enum.
- If a class declares more than one `@BPFTailCallTable`, disambiguate with
  `@TailCallSlot(value="A", table="<fieldName>")`.
- Slot index = `Enum.ordinal()`. Reorder the enum only if you understand
  every downstream `.ordinal()` reference.

## Compile-time errors (excerpt)

- Non-`BPFProgArray` field: `@BPFTailCallTable only applies to BPFProgArray fields`
- Missing sibling: `@BPFTailCallTable requires @BPFMapDefinition on the same field`
- Mismatch: `slots enum has N constant(s) but @BPFMapDefinition(maxEntries=M) disagrees`
- Bad name: `@TailCallSlot("Z") — no such constant in enum <FQN>. Known: [A, B, C]`

## Hot-swap via replaceSlot

`BPFProgArray.replaceSlot(int slot, ProgramHandle newHandle)` atomically
updates the prog-array entry using `bpf_map_update_elem`, so live tail-calls
see the new target immediately without any kernel restart:

```java
// Swap slot 0 from parseEth to newParseEth:
program.dispatch.replaceSlot(0, program.getProgramByName("newParseEth"));
```

This works with any program type and requires no special load-time wiring.

## Raw `BPFProgArray`

For cases where enum-based slot naming is unnecessary, use `BPFProgArray`
directly without `@BPFTailCallTable`:

```java
@BPF(license = "GPL")
public abstract class TailCallDemo extends BPFProgram implements XDPHook {

    static final int SLOT_DROP = 0;
    static final int SLOT_PASS = 1;

    @BPFMapDefinition(maxEntries = 2)
    BPFProgArray progs;

    @BPFFunction(section = "xdp")
    public xdp_action xdpDropPacket(Ptr<xdp_md> ctx) { return xdp_action.XDP_DROP; }

    @Override
    public xdp_action xdpHandlePacket(Ptr<xdp_md> ctx) {
        progs.tailCall(ctx, SLOT_PASS);
        return xdp_action.XDP_PASS;
    }

    public static void main(String[] args) throws Exception {
        try (TailCallDemo prog = BPFProgram.load(TailCallDemo.class)) {
            prog.progs.register(SLOT_DROP, prog.getProgramByName("xdpDropPacket"));
            prog.xdpAttach();
        }
    }
}
```

`register(int slot, ProgramHandle handle)` calls `bpf_map_update_elem`
under the hood — the same syscall `replaceSlot` uses, with no difference
in semantics.

## Limitations

- **Max chain depth**: the kernel allows at most 33 tail calls per original
  invocation. After that, `bpf_tail_call` returns without jumping and the
  helper returns `-ELOOP` internally; the tail-call silently does nothing.
- **Shared stack**: a tail-called program reuses the same stack frame as
  the caller. There is no stack isolation between stages — all stages share
  512 bytes.
- **Slot index**: slots are 0-indexed `u32` keys. `@BPFTailCallTable` uses
  `Enum.ordinal()` as the index. Reordering enum constants changes slot
  assignments without a compile error.
- **Program type**: every program loaded into a `BPFProgArray` must match
  the type of the program that calls it (e.g. all XDP, all TC). The kernel
  rejects mismatched types at load time.

## See also

- [`HelloTailCall.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java) — canonical sample.
- [`BPFProgArray.java`](https://github.com/parttimenerd/hello-ebpf/blob/main/bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java) — the underlying primitive.
