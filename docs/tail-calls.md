# Tail calls in hello-ebpf

BPF programs cannot recurse or exceed the verifier's instruction budget, so
long dispatch chains are split into stages connected by **tail calls**:
`bpf_tail_call(ctx, &prog_array, slot)` transfers execution to the program
at `prog_array[slot]` and never returns. hello-ebpf gives you two surfaces
for this pattern:

1. **Raw `BPFProgArray`** — the primitive. `progs.register(slot, handle)`
   plus `progs.tailCall(ctx, slot)`. See
   [`TailCallDemo.java`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/TailCallDemo.java).
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

## See also

- [`HelloTailCall.java`](../bpf-samples/src/main/java/me/bechberger/ebpf/samples/HelloTailCall.java) — canonical sample.
- [`BPFProgArray.java`](../bpf/src/main/java/me/bechberger/ebpf/bpf/map/BPFProgArray.java) — the underlying primitive.
