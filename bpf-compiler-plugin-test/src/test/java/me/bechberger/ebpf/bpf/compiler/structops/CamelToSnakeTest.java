package me.bechberger.ebpf.bpf.compiler.structops;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Acronym-aware camelCase -&gt; snake_case conversion tests for
 * {@link StructOpsValidator#camelToSnake(String)}.
 *
 * <p>The Guava-style boundary rule: insert an underscore before an uppercase
 * letter only when the previous letter is lowercase OR the next letter is
 * lowercase. This ensures {@code selectCPU} -&gt; {@code select_cpu} rather
 * than {@code select_c_p_u}.
 */
class CamelToSnakeTest {

    private static String convert(String s) {
        return StructOpsValidator.camelToSnake(s);
    }

    @Test
    void selectCPU() {
        assertEquals("select_cpu", convert("selectCPU"));
    }

    @Test
    void congAvoid() {
        assertEquals("cong_avoid", convert("congAvoid"));
    }

    @Test
    void httpServer() {
        assertEquals("http_server", convert("HTTPServer"));
    }

    @Test
    void parseXMLDoc() {
        assertEquals("parse_xml_doc", convert("parseXMLDoc"));
    }

    @Test
    void ssthresh() {
        assertEquals("ssthresh", convert("ssthresh"));
    }

    @Test
    void undoCwnd() {
        assertEquals("undo_cwnd", convert("undoCwnd"));
    }

    @Test
    void schedInit() {
        assertEquals("sched_init", convert("schedInit"));
    }

    @Test
    void initTask() {
        assertEquals("init_task", convert("initTask"));
    }
}
