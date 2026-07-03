# Annotations Catalog

!!! note "Placeholder"
    This page is a placeholder for content coming in Spec 2. See the
    [annotations audit](../superpowers/audit/audit-annotations.md)
    for the full symbol list.

Planned scope (five buckets):

**program-shape** — `@Kprobe`, `@Kretprobe`, `@Uprobe`, `@Uretprobe`, `@LSM`,
`@Tracepoint`, `@RawTracepoint`, `@Ksyscall`, `@Fentry`, `@Fexit`,
`@ProgramType`, `@Properties`, `@Property`, `@BPFFunction`, `@BPFInline`,
`@BPFTimer`, `@BPFMapDefinition`, `@BPFMapClass`

**type-system** — `@Unsigned`, `@Size`, `@Sizes`, `@Offset`, `@InlineUnion`,
`@PassByRef`, `@CustomType`, `@EnumMember`, `@OriginalName`, `@OriginalNames`

**pointer-flavour** — `@InArena`, `@Kptr`, `@TrustedPtr`, `@BPFNullable`,
`@BoundedBy`, `@AllowDirectVal`

**build/load** — `@Includes`, `@KernelBTF`, `@Requires`, `@SharedFrom`,
`@KFunc`, `@BuiltinBPFFunction`

**plugin-internal** — `@BPFImpl`, `@BPFInterface`, `@BPFAbstraction`,
`@BPFJavaInline`, `@BPFFunctionAlternative`, `@InternalBody`,
`@InternalMethodDefinition`, `@MethodIsBPFRelatedFunction`,
`@SuppressBPFWarning`, `@NotUsableInJava`, `@JavaOnly`
