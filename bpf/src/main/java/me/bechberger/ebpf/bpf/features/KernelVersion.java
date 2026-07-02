package me.bechberger.ebpf.bpf.features;

/**
 * Parsed kernel release triple. {@code raw} is the unparsed source string
 * (e.g. {@code "6.17.0-35-generic"}); {@code major}, {@code minor},
 * {@code patch} are decimal integers.
 *
 * <p>Kernel floor for hello-ebpf is 6.14 — the {@link #atLeast(int, int)}
 * predicate is the caller's guard against older kernels.
 */
public record KernelVersion(int major, int minor, int patch, String raw) {

    /** Parse a {@code uname -r}-style string. Rejects null / empty / non-numeric. */
    public static KernelVersion parse(String s) {
        if (s == null || s.isEmpty()) {
            throw new IllegalArgumentException("empty kernel version");
        }
        int i = 0, n = s.length();
        int[] parts = { 0, 0, 0 };
        int field = 0;
        boolean sawDigit = false;
        while (i < n && field < 3) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) {
                parts[field] = parts[field] * 10 + (c - '0');
                sawDigit = true;
                i++;
            } else if (c == '.' && sawDigit) {
                field++;
                sawDigit = false;
                i++;
            } else {
                break;
            }
        }
        if (parts[0] == 0 && parts[1] == 0 && !sawDigit && field == 0) {
            throw new IllegalArgumentException("not a kernel version: " + s);
        }
        return new KernelVersion(parts[0], parts[1], parts[2], s);
    }

    public boolean atLeast(int maj, int min) {
        if (major != maj) return major > maj;
        return minor >= min;
    }
}
