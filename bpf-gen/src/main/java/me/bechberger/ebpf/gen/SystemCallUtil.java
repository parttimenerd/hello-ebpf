package me.bechberger.ebpf.gen;

import me.bechberger.ebpf.gen.DeclarationParser.CannotParseException;
import me.bechberger.ebpf.gen.Generator.Type.FuncType;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Helps to create code for system calls
 * <p>
 * Parses {@code man 2 syscalls} to get the names and {@code man 2 name} to get the definitions for every system call
 */
public class SystemCallUtil {

    private static final Logger logger = Logger.getLogger(SystemCallUtil.class.getName());

    public record SystemCall(String name, String definition, @Nullable FuncType funcDefinition, String description) {
        public boolean isUnknown() {
            return definition.equals("unknown");
        }
    }

    public static List<SystemCall> parse() throws IOException, InterruptedException {
        Map<String, SystemCall> syscalls = new HashMap<>();

        var rawLines = callMan("syscalls");
        if (rawLines == null) {
            return List.of();
        }
        var lines = rawLines.stream().map(String::strip).toList();

        // take the line that starts with (excluding whitespace) "System call" and is followed by a line of
        // "────────────" (and more)
        // the lines following should be of format "name(number)  <some whitespace>  <kernel version>  <notes>" (but
        // ignore if notes is not empty)
        // stop at next empty line

        int syscallsLine = 0;
        for (int i = 0; i < lines.size(); i++) {
            if (lines.get(i).startsWith("System call") && lines.get(i + 1).matches("─+")) {
                syscallsLine = i;
                break;
            }
        }
        var syscallsStart = syscallsLine + 3;
        var syscallsLines = lines.subList(syscallsStart, lines.size()).stream().takeWhile(l -> !l.isBlank()).toList();

        Set<String> syscallNames = new HashSet<>();

        for (var line : syscallsLines) {
            var parts = line.split("\\s+");
            var name = parts[0].substring(0, parts[0].indexOf("("));
            syscallNames.add(name);
            if (syscalls.containsKey(name)) {
                continue;
            }
            var notes = parts.length > 2 ? parts[2] : "";
            if (!notes.isEmpty()) {
                logger.fine("Skipping syscall " + name + " with notes: " + notes);
                continue;
            }
            var manPage = callMan(name);
            if (manPage == null) {
                logger.fine("Skipping syscall " + name + " without proper man page");
                continue;
            }
            syscalls.putAll(parseManPage(name, manPage));
        }

        return syscalls.entrySet().stream().filter(e -> syscallNames.contains(e.getKey()))
                .sorted(Comparator.comparing(Entry::getKey)).map(Entry::getValue).collect(Collectors.toList());
    }

    private static @Nullable List<String> callMan(String name) {
        try {
            Process process = new ProcessBuilder(List.of("man", "2", name)).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            var lines = reader.lines().toList();
            if (process.waitFor() != 0 || lines.size() < 10) {
                return null;
            }
            return lines;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static Map<String, SystemCall> parseManPage(String name, @Nullable List<String> manPage) {
        // call man 2 name
        Map<String, SystemCall> ret = new HashMap<>();
        if (manPage == null) {
            return Map.of(name, new SystemCall(name, "unknown", null, "unknown"));
        }
        // find line that starts with SYNOPSIS
        var synopsis = findSynopsisSection(manPage);

        var wholeString = String.join("\n", manPage);

        for (var foundName : getSystemCallsFromManPage(manPage)) {
            try {

                var strippedDefinition = getDefinitionFromManPage(foundName, synopsis);
                var amendedDescription =
                        "__Man page for %s(2) from Linux__\n".formatted(name) + wholeString.lines().map(l -> "  " + l).collect(Collectors.joining("\n"));
                FuncType funcType = null;
                try {
                    funcType = DeclarationParser.parseFunctionDeclaration(strippedDefinition);
                } catch (Exception e) {
                    logger.log(Level.INFO, "Cannot parse function variable declaration: " + strippedDefinition, e);
                }
                ret.put(foundName, new SystemCall(foundName, strippedDefinition, funcType, amendedDescription));
            } catch (CannotParseException e) {
                logger.log(Level.FINE, "Could not parse definition for " + foundName + " in " + name + "(2): ", e);
            }
        }
        return ret;
    }

    private static @NotNull String getDefinitionFromManPage(String name, List<String> synopsis) {
        // find system call the normal way by finding a line that contains " name(" or "*name("
        // but count the open and closing parantheses and include the following lines till their count is equal

        for (int i = 0; i < synopsis.size(); i++) {
            var line = clean(synopsis.get(i));
            if ((line.contains(name + "(") || line.contains("*" + name + "(")) && (line.endsWith(";") || line.endsWith(")") || line.endsWith(",") || line.endsWith("("))) {
                // if it starts directly with "name(" or "*name(" then take the return type from the previous line
                var def = findWholeDefinition(name, synopsis, i);
                if (def != null) {
                    return def;
                }
            }
        }

        // now try another way
        var known = " syscall(SYS_" + name;
        var known2 = "*syscall(SYS_" + name;

        for (int i = 0; i < synopsis.size(); i++) {
            var line = synopsis.get(i).strip();
            if (line.contains(known) || line.contains(known2)) {
                var combined = findWholeDefinition(name, synopsis, i);
                if (combined == null) {
                    throw new CannotParseException("Could not parse definition for " + name);
                }
                var usedKnown = combined.contains(known) ? known : known2;

                var returnType = combined.substring(0, combined.indexOf(usedKnown));
                if (usedKnown.startsWith("*")) {
                    returnType = returnType.strip() + "*";
                }
                var args = Arrays.stream(combined.substring(combined.indexOf(usedKnown) + usedKnown.length()).split(
                        "\\)")[0].split(",")).map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.joining(", "));
                // something like int syscall(SYS_ioprio_get, int which, int who);
                // find definition and create C definition yourself
                return returnType + " " + name + "(" + args + ");";
            }
        }
        throw new CannotParseException("Could not parse definition for " + name);
    }

    private static @Nullable String findWholeDefinition(String name, List<String> lines, int startIndex) {
        var line = clean(lines.get(startIndex));
        if (line.startsWith(name + "(") || line.startsWith("*" + name + "(")) {
            if (startIndex == 0) {
                return null;
            }
            line = clean(lines.get(startIndex - 1)) + " " + line;
        }
        var open = line.chars().filter(c -> c == '(').count();
        var close = line.chars().filter(c -> c == ')').count();
        String definition = line.strip();
        int j = startIndex + 1;
        while (open != close) {
            line = clean(lines.get(j));
            if (!definition.endsWith("(") && !line.startsWith(")")) {
                definition += " ";
            }
            definition += line;
            open += line.chars().filter(c -> c == '(').count();
            close += line.chars().filter(c -> c == ')').count();
            j++;
            if (j > startIndex + 10) { // probably some error
                throw new CannotParseException("Could parse definition for " + name);
            }
        }
        return definition;
    }

    static Map<String, SystemCallUtil.SystemCall> parseManPage(String name, String manPage) {
        return parseManPage(name, Arrays.stream(manPage.split("\n")).toList());
    }

    /**
     * Remove comments and leading and trailing whitespace from a string
     */
    static String clean(String string) {
        return string.replaceAll("/\\*.*?\\*/", "").replaceAll("//.*", "").strip();
    }

    private static List<String> findSynopsisSection(List<String> lines) {
        int synIndex = lines.indexOf("SYNOPSIS");
        int descIndex = lines.indexOf("DESCRIPTION");
        return lines.subList(synIndex + 1, descIndex == -1 ? lines.size() : descIndex);
    }

    private static List<String> getSystemCallsFromManPage(List<String> lines) {
        var namesLine = lines.get(lines.indexOf("NAME") + 1);
        return Arrays.stream(namesLine.trim().split("[–-]")[0].split(",")).map(String::trim).toList();
    }
}