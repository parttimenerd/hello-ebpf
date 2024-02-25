package me.bechberger.ebpf.shared;

import me.bechberger.ebpf.shared.util.LineReader;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Function;

import static me.bechberger.ebpf.shared.Constants.TRACEFS;

/**
 * TraceLog provides a simple interface to the kernel debug trace pipe.
 * <p>
 * Inspired transitively (and probably derived) from the bcc project
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
    public TraceFields readFields() {
        while (true) {
            String tracedLine = traceFile.readLine();
            if (tracedLine == null) return null;
            // don't print messages related to lost events
            if (tracedLine.startsWith("CPU:")) continue;
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
     * Read from the kernel debug trace pipe and return one line
     */
    public String readLine() {
        return traceFile.readLine();
    }

    /**
     * Read from the kernel debug trace pipe and print on stdout.
     * @param format optional function to format the output
     *
     * Example
     * {@snippet
     *   printLoop(f -> f.format("pid {1}, msg = {5}"));
     * }
     */
    public void printLoop(@Nullable Function<TraceFields, @Nullable String> format) {
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
            if (line != null) {
                System.out.println(line);
                System.out.flush();
            }
        }
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
}
