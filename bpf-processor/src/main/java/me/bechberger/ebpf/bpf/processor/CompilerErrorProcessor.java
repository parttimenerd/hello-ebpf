package me.bechberger.ebpf.bpf.processor;

import com.diogonunes.jcolor.Ansi;
import com.diogonunes.jcolor.AnsiFormat;
import com.diogonunes.jcolor.Attribute;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Processes compiler errors from Clang
 */
public record CompilerErrorProcessor(List<PerFileOrRaw> errors) {

    sealed interface PerFileOrRaw {
        String toPrettyString(boolean colorize);
    }

    record CompilerError(Path file, int line, int column, String header, String body) {
        boolean isFatal() {
            return header.startsWith("fatal error:");
        }

        boolean isWarning() {
            return header.startsWith("warning:");
        }

        boolean isError() {
            return header.startsWith("error:");
        }

        boolean isNote() {
            return header.startsWith("note:");
        }

        public String toPrettyString(boolean colorize) {
            String message = String.format("%s:%d:%d: %s\n%s", file.toString().endsWith(".c") ? file.getFileName().toString() : "<bpf program>", line, column, header, body);
            if (colorize) {
                var color = isFatal() || isError() ? Attribute.RED_TEXT() : isWarning() ? Attribute.YELLOW_TEXT() : Attribute.NONE();
                message = Ansi.colorize(message, color);
            }
            List<String> suggestions = suggestionsForMessage(message);
            if (!suggestions.isEmpty()) {
                message += "\nSuggestions:\n" + String.join("\n", suggestions);
            }
            return message;
        }
    }

    record RawMessage(String message) implements CompilerErrorProcessor.PerFileOrRaw {
        @Override
        public String toPrettyString(boolean colorize) {
            return message;
        }
    }

    record CompilerErrorsPerFile(Path file, List<CompilerErrorProcessor.CompilerError> errors) implements PerFileOrRaw {
        boolean hasErrors() {
            return !errors.isEmpty();
        }

        record ErrorNumbers(int fatal, int warning, int error) {
            ErrorNumbers(List<CompilerError> errors) {
                this((int) errors.stream().filter(CompilerError::isFatal).count(),
                        (int) errors.stream().filter(CompilerError::isWarning).count(),
                        (int) errors.stream().filter(CompilerError::isError).count());
            }

            String toPrettyString() {
                List<String> parts = new ArrayList<>();
                if (fatal > 0) {
                    parts.add(java.lang.String.format("%d fatal error%s", fatal, fatal > 1 ? "s" : ""));
                }
                if (error > 0) {
                    parts.add(java.lang.String.format("%d error%s", error, error > 1 ? "s" : ""));
                }
                if (warning > 0) {
                    parts.add(java.lang.String.format("%d warning%s", warning, warning > 1 ? "s" : ""));
                }
                return java.lang.String.join(", ", parts);
            }
        }
        @Override
        public String toPrettyString(boolean colorize) {
            if (!hasErrors()) {
                return "";
            }
            String errorString = "Summary: " + new ErrorNumbers(errors).toPrettyString();
            return Stream.concat(Stream.of(file.toAbsolutePath() + " has problems:" + (errors.size() > 1 ? "\n" + errorString : "")),
                    errors.stream().map(c -> c.toPrettyString(colorize))).collect(Collectors.joining("\n"));
        }
    }

    public static CompilerErrorProcessor fromClangOutput(String llvmOutput, Path bpfFile) {
        List<PerFileOrRaw> errors = new ArrayList<>();
        String[] lines = llvmOutput.split("\n");
        Path currentFile = null;
        List<CompilerError> currentErrors = new ArrayList<>();
        for (int i = 0; i < lines.length; i++) {
            String errorLine = lines[i];
            if (errorLine.matches(".*:[0-9]+:[0-9]+:.*:.*")) {
                // <file>:line:column: header
                var parts = errorLine.split(":", 4);
                var file = parts[0].equals("<stdin>") ? bpfFile : Path.of(parts[0]);
                var line = Integer.parseInt(parts[1]);
                var column = Integer.parseInt(parts[2]);
                var header = parts[3];
                List<String> bodyLines = new ArrayList<>();
                for (i++; i < lines.length; i++) {
                    if (lines[i].matches(".*:[0-9]+:[0-9]+:.*:.*")) {
                        i--;
                        break;
                    }
                    bodyLines.add(lines[i]);
                }
                var body = String.join("\n", bodyLines);
                var error = new CompilerError(file, line, column, header.strip(), body);
                if (currentFile == null) {
                    currentFile = file;
                }
                currentErrors.add(error);
                if (!currentFile.equals(file)) {
                    errors.add(new CompilerErrorsPerFile(currentFile, currentErrors));
                    currentErrors = new ArrayList<>();
                    currentFile = file;
                }
            } else {
                errors.add(new RawMessage(errorLine));
            }
        }
        if (!currentErrors.isEmpty()) {
            errors.add(new CompilerErrorsPerFile(currentFile, currentErrors));
        }
        return new CompilerErrorProcessor(errors);
    }

    String toPrettyString(boolean colorize) {
        return errors.stream().map(e -> e.toPrettyString(colorize)).collect(Collectors.joining("\n"));
    }

    private static List<String> suggestionsForMessage(String message) {
        List<String> suggestions = new ArrayList<>();
        if (message.contains(" fatal error: 'bits/libc-header-start.h' file not found")) {
            suggestions.add("Try to install gcc-multilib");
        }
        if (message.contains(" fatal error: 'bpf_helpers.h' file not found")) {
            suggestions.add("Replace `#include 'bpf_helpers.h` with `#include <bpf/bpf_helpers.h>`");
        }
        return suggestions;
    }
}
