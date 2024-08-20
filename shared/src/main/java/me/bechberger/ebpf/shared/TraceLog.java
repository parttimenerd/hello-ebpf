package me.bechberger.ebpf.shared;

import me.bechberger.ebpf.shared.util.LineReader;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static me.bechberger.ebpf.shared.Constants.TRACEFS;

/**
 * TraceLog provides a simple interface to the kernel debug trace pipe.
 */
public class TraceLog {

    public record TraceFields(String line, String task, int pid, String cpu, String flags, double ts, String msg) {

        /**
         * Format the fields using the given format string
         * <p>
         * <ul>
         *     <li>{0} - task</li>
         *     <li>{1} - pid</li>
         *     <li>{2} - cpu</li>
         *     <li>{3} - flags</li>
         *     <li>{4} - ts (time stamp)</li>
         *     <li>{5} - msg</li>
         *     <li>Example: "{0} ({1}) on cpu {2} at {4}: {5}"</li>
         * </ul>
         * @param fmt
         * @return
         */
        public String format(String fmt) {
            String fields = fmt;
            fields = fields.replace("{0}", task);
            fields = fields.replace("{1}", String.valueOf(pid));
            fields = fields.replace("{2}", cpu);
            fields = fields.replace("{3}", flags);
            fields = fields.replace("{4}", String.valueOf(ts));
            fields = fields.replace("{5}", msg);
            return fields;
        }
    }

    private static TraceLog instance = new TraceLog();

    private final LineReader traceFile;

    private TraceLog() {
        try {
            traceFile = new LineReader(TRACEFS.resolve("trace_pipe"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static TraceLog getInstance() {
        if (instance == null) {
            instance = new TraceLog();
        }
        return instance;
    }

    public static void close() {
        if (instance != null) {
            instance.traceFile.close();
            instance = null;
        }
    }


    /**
     * Read from the kernel debug trace pipe and return the fields.
     * Returns null if no line was read.
     * <p/>
     * Currently, doesn't support non-blocking mode
     */
    public @Nullable TraceFields readFields() {
        while (true) {
            String tracedLine = traceFile.readLine();
            if (tracedLine == null) return null;
            // don't print messages related to lost events
            if (tracedLine.startsWith("CPU:")) continue;
            if (tracedLine.length() < 17) continue;
            try {
                var task = tracedLine.substring(0, 16).strip();
                var line = tracedLine.substring(17);
                var tsEnd = line.indexOf(":");
                var pidCpuFlagsTs = line.substring(0, tsEnd).split(" +");
                var pid = Integer.parseInt(pidCpuFlagsTs[0]);
                var cpu = pidCpuFlagsTs[1].substring(1, pidCpuFlagsTs[1].length() - 1);
                var flags = pidCpuFlagsTs[2];
                var ts = Double.parseDouble(pidCpuFlagsTs[3]);
                line = line.substring(tsEnd + 1);
                int symEnd = line.indexOf(":");
                var msg = line.substring(symEnd + 2);
                return new TraceFields(tracedLine, task, pid, cpu, flags, ts, msg);
            } catch (NumberFormatException e) {
                return new TraceFields(tracedLine, "Unknown", 0, "Unknown", "Unknown", 0.0, "Unknown");
            }
        }
    }

    /**
     * Read from the kernel debug trace pipe and return one line, might block
     */
    public @Nullable String readLine() {
        return traceFile.readLine();
    }

    public @Nullable String readLineIfPossible() {
        return traceFile.readLineIfPossible();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * <p>
     * Example
     * {@snippet :
     *   printLoop(f -> f.format("pid {1}, msg = {5}"), false);
     * }
     * @param format optional function to format the output
     * @param removeBPFTracePrintk remove the string {@code bpf_trace_printk: } from the messages
     */
    public void printLoop(@Nullable Function<TraceFields, @Nullable String> format, boolean removeBPFTracePrintk) {
        while (true) {
            String line = null;
            if (format != null) {
                var fields = readFields();
                if (fields != null) {
                    line = format.apply(fields);
                }
            } else {
                line = traceFile.readLine();
            }
            if (line != null && removeBPFTracePrintk) {
                line = line.replace("bpf_trace_printk: ", "");
            }
            if (line != null && !line.isEmpty()) {
                System.out.println(line);
                System.out.flush();
            }
        }
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * <p>
     * Example
     * {@snippet :
     *   printLoop(f -> f.format("pid {1}, msg = {5}"));
     * }
     * @param format optional function to format the output
     */
    public void printLoop(@Nullable Function<TraceFields, @Nullable String> format) {
        printLoop(format, false);
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * @param fmt optional format string
     */
    public void printLoop(@Nullable String fmt) {
        if (fmt != null) {
            printLoop(fields -> fields.format(fmt));
            return;
        }
        printLoop((Function<TraceFields, String>) null);
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     */
    public void printLoop() {
        printLoop((String) null);
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * @param removeBPFTracePrintk remove the string {@code bpf_trace_printk: } from the messages
     */
    public void printLoop(boolean removeBPFTracePrintk) {
        if (removeBPFTracePrintk) {
            printLoop((Function<TraceFields, String>) null, true);
            return;
        }
        printLoop((Function<TraceFields, String>) null);
    }

    public List<String> readAllAvailableLines() {
        return readAllAvailableLines(Duration.ZERO);
    }

    public List<String> readAllAvailableLines(Duration waitAtMost) {
        List<String> lines = new ArrayList<>();
        long start = System.nanoTime();
        while (Duration.ofNanos(System.nanoTime() - start).compareTo(waitAtMost) < 0) {
            while (traceFile.ready()) {
                lines.add(traceFile.readLine());
                start = System.nanoTime();
            }
        }
        return lines;
    }
}
