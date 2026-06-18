package me.bechberger.ebpf.bpf.compiler;

import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.Name;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.Param;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.ParamName;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.ParamType;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.Params;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.Return;
import me.bechberger.ebpf.bpf.compiler.MethodHeaderTemplate.TemplatePart.Verbatim;
import me.bechberger.ebpf.bpf.compiler.MethodTemplateCache.TemplateRenderException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link MethodHeaderTemplate#parse(String)}. The header-template language is a
 * smaller cousin of {@link MethodTemplate}'s — only $name, $return, $params, $param$N$,
 * $paramName$N$, $paramType$N$ are recognised. Pin the edge cases.
 */
class MethodHeaderTemplateParseTest {

    @Test
    void emptyTemplateRejected() {
        var ex = assertThrows(TemplateRenderException.class,
                () -> MethodHeaderTemplate.parse(""));
        assertTrue(ex.getMessage().contains("Empty"));
    }

    @Test
    void trailingSemicolonIsStripped() {
        var t = MethodHeaderTemplate.parse("$return $name($params);");
        assertEquals("$return $name($params)", t.raw());
    }

    @Test
    void bareNameExpandsToCanonicalSignature() {
        // $name alone → "$return $name($params)" expansion.
        var t = MethodHeaderTemplate.parse("$name");
        assertEquals(6, t.parts().size(), "expected: Return ' ' Name '(' Params ')'");
        assertInstanceOf(Return.class, t.parts().get(0));
        assertInstanceOf(Name.class, t.parts().get(2));
        assertInstanceOf(Params.class, t.parts().get(4));
    }

    @Test
    void paramNumbersAreOneIndexedInTemplate() {
        var t = MethodHeaderTemplate.parse("$paramType1 $paramName1");
        assertEquals(0, ((ParamType) t.parts().get(0)).n());
        assertEquals(0, ((ParamName) t.parts().get(2)).n());
    }

    @Test
    void paramAndParamsAreDistinct() {
        var t = MethodHeaderTemplate.parse("$param1 $params");
        assertInstanceOf(Param.class, t.parts().get(0));
        assertInstanceOf(Params.class, t.parts().get(2));
    }

    @Test
    void unknownPlaceholderRejected() {
        assertThrows(TemplateRenderException.class,
                () -> MethodHeaderTemplate.parse("$bogus"));
    }

    @Test
    void paramWithoutNumberThrowsTemplateRenderException() {
        // Regression test: $param without a digit used to fall through to Integer.parseInt("")
        // and throw a raw NumberFormatException. It should now produce TemplateRenderException.
        var ex = assertThrows(TemplateRenderException.class,
                () -> MethodHeaderTemplate.parse("$param"));
        assertTrue(ex.getMessage().contains("number"), "msg: " + ex.getMessage());
    }

    @Test
    void paramTypeWithoutNumberThrowsTemplateRenderException() {
        assertThrows(TemplateRenderException.class,
                () -> MethodHeaderTemplate.parse("$paramType"));
    }

    @Test
    void paramNameWithoutNumberThrowsTemplateRenderException() {
        assertThrows(TemplateRenderException.class,
                () -> MethodHeaderTemplate.parse("$paramName"));
    }

    @Test
    void rawTemplateIsPreserved() {
        var t = MethodHeaderTemplate.parse("static $return $name($params)");
        assertEquals("static $return $name($params)", t.raw());
    }

    @Test
    void verbatimBeforePlaceholdersIsPreserved() {
        var t = MethodHeaderTemplate.parse("inline __attribute__((noinline)) $name");
        // First part is verbatim "inline __attribute__((noinline)) ", then Name (no expansion
        // because there are multiple parts).
        assertInstanceOf(Verbatim.class, t.parts().get(0));
        assertEquals("inline __attribute__((noinline)) ", ((Verbatim) t.parts().get(0)).verb());
        assertInstanceOf(Name.class, t.parts().get(1));
    }
}
