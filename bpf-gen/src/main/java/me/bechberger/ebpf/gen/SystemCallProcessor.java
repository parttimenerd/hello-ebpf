package me.bechberger.ebpf.gen;

import com.squareup.javapoet.*;
import com.squareup.javapoet.TypeSpec.Builder;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.bpf.raw.Lib.syscall;
import me.bechberger.ebpf.gen.DeclarationParser.CannotParseException;
import me.bechberger.ebpf.gen.Generator.GeneratorConfig;
import me.bechberger.ebpf.gen.Generator.NameTranslator;
import me.bechberger.ebpf.gen.Generator.Type;
import me.bechberger.ebpf.gen.Generator.Type.FuncType;
import me.bechberger.ebpf.gen.Generator.TypeJavaFiles;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.lang.model.element.Modifier;
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
public class SystemCallProcessor {

    private static final Logger logger = Logger.getLogger(SystemCallProcessor.class.getName());

    public record SystemCall(String name, String definition, @Nullable FuncType funcDefinition, String description) {
        public boolean isUnknown() {
            return definition.equals("unknown");
        }
    }

    /** Add types from https://github.com/torvalds/linux/blob/master/include/linux/types.h */
    public static NameTranslator addNecessaryTypesToNameTranslator(NameTranslator translator) {
        translator.put("socklen_t", KnownTypes.getKnownInt(64, false).orElseThrow());
        translator.put("idtype_t", KnownTypes.getKnownInt(32, true).orElseThrow());
        translator.put("id_t", "pid_t");
        translator.put("off64_t", KnownTypes.getKnownInt(64, true).orElseThrow());
        translator.setThrowUnknownTypeException(true);
        return translator;
    }

    public static List<SystemCall> parse(NameTranslator translator) throws IOException, InterruptedException {
        Map<String, SystemCall> syscalls = new HashMap<>();
        addNecessaryTypesToNameTranslator(translator);

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
            if (parts.length < 2 || !parts[0].contains("(")) {
                continue;
            }
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
            syscalls.putAll(parseManPage(translator, name, manPage));
        }

        return syscalls.entrySet().stream().filter(e -> syscallNames.contains(e.getKey()))
                .sorted(Entry.comparingByKey()).map(Entry::getValue).collect(Collectors.toList());
    }

    static TypeJavaFiles createSystemClassInterface(String basePackage, List<SystemCall> systemCalls, TypeJavaFiles generated) {
        var generator = new Generator(basePackage);
        systemCalls.stream().filter(s -> !s.isUnknown()).forEach(s -> generator.addAdditionalType(s.funcDefinition()));
        return generator.generateJavaFiles(new GeneratorConfig("SystemCallHooks") {
            @Override
            public String classDescription() {
                return "Interface for implement enter and exit hooks for specific system calls";
            }

            @Override
            public List<MethodSpec> createMethodSpec(Generator gen, Type type) {
                if (type instanceof FuncType) {
                    return createSystemCallRelatedInterfaceMethods(gen, (FuncType) type);
                }
                return List.of();
            }

            @Override
            public Builder createTypeSpecBuilder(Generator gen, String className) {
                return TypeSpec.interfaceBuilder(className).addModifiers(Modifier.PUBLIC)
                        .addAnnotation(AnnotationSpec.builder(SuppressWarnings.class)
                        .addMember("value", "$S", "unused").build());
            }

            @Override
            public List<Class<?>> preimportedClasses() {
                return List.of(BPFFunction.class, SuppressWarnings.class);
            }

            @Override
            public List<String> additionalImports() {
                return generated.generateStaticImportsForAll();
            }
        });
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

    private static Map<String, SystemCall> parseManPage(NameTranslator translator, String name, @Nullable List<String> manPage) {
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
                var javadoc = new Markdown().markdownToHTML(amendedDescription);
                FuncType funcType = null;
                try {
                    funcType = DeclarationParser.parseFunctionDeclaration(translator, strippedDefinition).setJavaDoc(javadoc);
                } catch (Exception e) {
                    //logger.log(Level.INFO, "Cannot parse function variable declaration: " + strippedDefinition, e);
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

    static Map<String, SystemCallProcessor.SystemCall> parseManPage(String name, String manPage) {
        return parseManPage(new Generator("").createNameTranslator(), name, manPage);
    }

    static Map<String, SystemCallProcessor.SystemCall> parseManPage(NameTranslator translator, String name, String manPage) {
        return parseManPage(translator, name, Arrays.stream(manPage.split("\n")).toList());
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

    /** From snake to camel case, upper case */
    static String toCamelCase(String string) {
        return Arrays.stream(string.split("_")).filter(s -> !s.isEmpty()).map(s -> s.substring(0, 1).toUpperCase() + (s.length() == 1 ? "" : s.substring(1))).collect(Collectors.joining());
    }

    /**
     * Generates the fentry and fexit related interface methods for a given system call.
     */
    static List<MethodSpec> createSystemCallRelatedInterfaceMethods(Generator gen, FuncType syscall) {
        var ret = new ArrayList<MethodSpec>();
        var m = createSystemCallRelatedMethod(gen, syscall, true, false, null);
        ret.add(m);
        ret.add(createSystemCallRelatedMethod(gen, syscall, false, false, m));
        ret.add(createSystemCallRelatedMethod(gen, syscall, true, true, m));
        ret.add(createSystemCallRelatedMethod(gen, syscall, false, true, m));
        return ret;
    }

    static MethodSpec createSystemCallRelatedMethod(Generator gen, FuncType syscall, boolean isEntry, boolean isKProbe, @Nullable MethodSpec refJavaDoc) {
        var impl = syscall.impl();

        String section;
        String macro;
        String namePrefix;
        if (isEntry) {
            if (isKProbe) {
                section = "kprobe/do_" + syscall.name();
                macro = "BPF_KPROBE";
                namePrefix = "kprobeEnter";
            } else {
                section = "fentry/do_" + syscall.name();
                macro = "BPF_PROG";
                namePrefix = "enter";
            }

        } else {
            if (isKProbe) {
                section = "kretprobe/do_" + syscall.name();
                macro = "BPF_KRETPROBE";
                namePrefix = "kprobeExit";
            } else {
                section = "fexit/do_" + syscall.name();
                macro = "BPF_PROG";
                namePrefix = "exit";
            }
        }

        String docFmt;
        if (isEntry) {
            docFmt = """
                        Enter the system call {@code %s}
                        %s""";
        } else {
            docFmt = """
                        Exit the system call {@code %s}
                        %s""";
            if (!impl.returnsVoid()) {
                docFmt += """
                        
                        @param ret return value of the system call
                        """;
            }
        }
        String doc = docFmt.formatted(syscall.name(), ""); // TODO: fix java doc
        /*if (refJavaDoc == null) {
            doc = docFmt.formatted(syscall.name(), clean(syscall.javaDoc()));
        } else {
            doc = docFmt.formatted(syscall.name(), "@see #" + refJavaDoc.name);
        }*/
        var spec = impl.toMethodSpec(gen, namePrefix + toCamelCase(syscall.name()), doc);

        // problem: this is not an interface method, and it has the wrong annotation
        var builder = spec.toBuilder();
        builder.modifiers.clear();
        builder.addModifiers(Modifier.PUBLIC, Modifier.DEFAULT);
        builder.annotations.clear();
        var headerTemplateArgs = impl.parameters().stream().map(p -> p.type().resolve().toCType().toPrettyString() + " " + p.name()).collect(Collectors.toList());
        if (!isEntry && !impl.returnsVoid()) {
            headerTemplateArgs.add(impl.returnType().toCType().toPrettyString() + " ret");
            builder.parameters.add(ParameterSpec.builder(impl.returnType().toTypeName(gen), "ret").build());
        }

        builder.returns(TypeName.VOID);
        builder.varargs(false);
        var headerTemplate = "int %s(do_%s%s%s)".formatted(
                macro,
                syscall.name(),
                isEntry ? "" : "_exit",
                headerTemplateArgs.isEmpty() ? "" : ", " + String.join(", ", headerTemplateArgs)
        );
        builder.addAnnotation(
                AnnotationSpec.builder(ClassName.get("", BPFFunction.class.getSimpleName()))
                        .addMember("headerTemplate", "$S", headerTemplate)
                        .addMember("lastStatement", "$S", "return 0;")
                        .addMember("section", "$S", section).build());
        return builder.build();
    }
}