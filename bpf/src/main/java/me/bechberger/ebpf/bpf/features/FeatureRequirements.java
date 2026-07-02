package me.bechberger.ebpf.bpf.features;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.map.MapTypeId;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Declarative list of features a program needs. Populated per-program by
 * the annotation processor (in a later plan); consumed by {@link #enforce}
 * inside {@link BPFProgram#load(Class)}.
 */
public final class FeatureRequirements {

    /** Discriminated union of required features. */
    public sealed interface Item {
        record ProgramType(BPFProgramType t, String since)  implements Item {}
        record MapType(MapTypeId t, String since)           implements Item {}
        record Helper(BPFHelper h, String since)            implements Item {}
        record Kfunc(String name, @Nullable String module)  implements Item {}
        record StructOps(String kernelStructName, String since) implements Item {}
        record AttachType(BPFAttachType t, String since)    implements Item {}
    }

    private final String programName;
    private final List<Item> items;

    private FeatureRequirements(String programName, List<Item> items) {
        this.programName = programName;
        this.items = List.copyOf(items);
    }

    public String programName() { return programName; }
    public List<Item> items()   { return items; }

    /** Throws {@link BPFProgram.BPFLoadError} subclasses on the first miss. */
    public static void enforce(FeatureRequirements req) {
        for (Item it : req.items) {
            switch (it) {
                case Item.ProgramType p -> require(
                        Features.hasProgramType(p.t()),
                        "program_type " + p.t().name(), p.since());
                case Item.MapType m -> require(
                        Features.hasMapType(m.t()),
                        "map_type " + m.t().name(), m.since());
                case Item.Helper h -> require(
                        Features.hasHelper(h.h()),
                        "helper " + h.h().name(), h.since());
                case Item.Kfunc k -> {
                    if (!Features.hasKfunc(k.name(),
                            k.module() == null ? null : k.module())) {
                        throw new BPFProgram.BPFLoadError.MissingKfunc(
                                k.name(), req.programName);
                    }
                }
                case Item.StructOps s -> require(
                        Features.hasStructOps(s.kernelStructName()),
                        "struct_ops " + s.kernelStructName(), s.since());
                case Item.AttachType a -> require(
                        Features.hasAttachType(a.t()),
                        "attach_type " + a.t().name(), a.since());
            }
        }
    }

    private static void require(boolean present, String feature, String since) {
        if (!present) {
            throw new BPFProgram.BPFLoadError.UnsupportedKernel(feature, since);
        }
    }

    public static final class Builder {
        private String programName = "<unknown>";
        private final List<Item> items = new ArrayList<>();

        public Builder programName(String s) { this.programName = s; return this; }
        public Builder programType(BPFProgramType t, String since) {
            items.add(new Item.ProgramType(t, since)); return this;
        }
        public Builder mapType(MapTypeId t, String since) {
            items.add(new Item.MapType(t, since)); return this;
        }
        public Builder helper(BPFHelper h, String since) {
            items.add(new Item.Helper(h, since)); return this;
        }
        public Builder kfunc(String name) {
            items.add(new Item.Kfunc(name, null)); return this;
        }
        public Builder kfunc(String name, String module) {
            items.add(new Item.Kfunc(name, module)); return this;
        }
        public Builder structOps(String name, String since) {
            items.add(new Item.StructOps(name, since)); return this;
        }
        public Builder attachType(BPFAttachType t, String since) {
            items.add(new Item.AttachType(t, since)); return this;
        }
        public FeatureRequirements build() {
            return new FeatureRequirements(programName, Collections.unmodifiableList(items));
        }
    }
}
