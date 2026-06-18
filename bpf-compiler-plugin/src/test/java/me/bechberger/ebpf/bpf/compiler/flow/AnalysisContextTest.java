package me.bechberger.ebpf.bpf.compiler.flow;

import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.TreeVisitor;
import org.junit.jupiter.api.Test;

import javax.lang.model.element.Name;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** {@link AnalysisContext} blackboard semantics — slot routing, identity keying, defaults. */
class AnalysisContextTest {

    /** Cheap stub Tree to avoid pulling in javac for these tests. */
    private static Tree stubTree() {
        return new LiteralTree() {
            @Override public Object getValue() { return null; }
            @Override public Kind getKind() { return Kind.NULL_LITERAL; }
            @Override public <R, D> R accept(TreeVisitor<R, D> visitor, D data) {
                return visitor.visitLiteral(this, data);
            }
        };
    }

    @Test
    void regionOfDefaultsToUnknown() {
        var ctx = new AnalysisContext();
        assertEquals(MemoryRegion.UNKNOWN, ctx.regionOf(stubTree()));
    }

    @Test
    void regionAtLookupRespectsIdentity() {
        var ctx = new AnalysisContext();
        var t1 = stubTree();
        var t2 = stubTree();
        ctx.regionAt.put(t1, MemoryRegion.USER);
        assertEquals(MemoryRegion.USER, ctx.regionOf(t1));
        assertEquals(MemoryRegion.UNKNOWN, ctx.regionOf(t2));
    }

    @Test
    void nullabilityOfDefaultsToUnknown() {
        var ctx = new AnalysisContext();
        assertEquals(NullabilityValue.UNKNOWN, ctx.nullabilityOf(stubTree()));
    }

    @Test
    void suppressionsRecognisesAllAndCategory() {
        var ctx = new AnalysisContext();
        var t = stubTree();
        ctx.suppressionsAt.put(t, Set.of("region.mixing"));
        assertTrue(ctx.isSuppressed(t, "region.mixing"));
        assertFalse(ctx.isSuppressed(t, "other.cat"));
        ctx.suppressionsAt.put(t, Set.of("all"));
        assertTrue(ctx.isSuppressed(t, "anything"));
    }

    @Test
    void slotsAreTypeSafeAndIdentityKeyed() {
        AnalysisContext.Slot<String> slotA = AnalysisContext.slot("a");
        AnalysisContext.Slot<Integer> slotB = AnalysisContext.slot("b");
        var ctx = new AnalysisContext();
        var t = stubTree();
        ctx.put(slotA, t, "hello");
        ctx.put(slotB, t, 42);
        assertEquals("hello", ctx.get(slotA, t));
        assertEquals(42, ctx.get(slotB, t));
        assertNull(ctx.get(slotA, stubTree()));
    }

    @Test
    void packetGuardedSetUsesIdentity() {
        var ctx = new AnalysisContext();
        var t1 = stubTree();
        var t2 = stubTree();
        ctx.packetGuarded.add(t1);
        assertTrue(ctx.packetGuarded.contains(t1));
        assertFalse(ctx.packetGuarded.contains(t2));
    }

    @Test
    void programTypeDefaultsToUnknown() {
        assertEquals(AnalysisContext.ProgramTypeValue.UNKNOWN, new AnalysisContext().programType);
    }
}
