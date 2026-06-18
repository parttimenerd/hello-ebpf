package me.bechberger.ebpf.bpf.compiler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Coverage for the static {@link HelperContextPass#extractHelperName} parser. */
class HelperContextPassExtractHelperNameTest {

    @Test
    void plainCall() {
        assertEquals("bpf_get_current_task",
                HelperContextPass.extractHelperName("bpf_get_current_task()"));
    }

    @Test
    void callWithArgs() {
        assertEquals("bpf_xdp_adjust_head",
                HelperContextPass.extractHelperName("bpf_xdp_adjust_head($1, $2)"));
    }

    @Test
    void leadingCastIsStripped() {
        assertEquals("bpf_get_current_pid_tgid",
                HelperContextPass.extractHelperName("(long) bpf_get_current_pid_tgid()"));
    }

    @Test
    void returnsNullForNonBpfFunction() {
        assertNull(HelperContextPass.extractHelperName("some_other_helper()"));
        assertNull(HelperContextPass.extractHelperName("$name($args)"));
    }

    @Test
    void returnsNullForEmptyOrNonCall() {
        assertNull(HelperContextPass.extractHelperName(""));
        assertNull(HelperContextPass.extractHelperName(null));
        assertNull(HelperContextPass.extractHelperName("bpf_no_parens"));
    }

    @Test
    void doubledLeadingCastIsStripped() {
        // Some templates stack casts (e.g. forcing both width and signedness). The strip loop
        // should peel them off until the actual call symbol is reached.
        assertEquals("bpf_get_current_pid_tgid",
                HelperContextPass.extractHelperName("(int) (long) bpf_get_current_pid_tgid()"));
    }

    @Test
    void unclosedLeadingCastReturnsNull() {
        // Defensive: malformed template like "(long bpf_foo()" — no closing paren before symbol.
        // The strip loop bails out by returning null.
        assertNull(HelperContextPass.extractHelperName("(long bpf_foo()"));
    }
}
