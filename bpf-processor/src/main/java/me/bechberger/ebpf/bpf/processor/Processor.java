package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.TypeSpec;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Statement.Define;
import me.bechberger.ebpf.bpf.processor.TypeProcessor.TypeProcessorResult;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.*;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

/**
 * Annotation processor that processes classes annotated with {@code @BPF}.
 * <p>
 * The processor compiles the eBPF program and takes care of {@code @Type} inner types.
 */
@SupportedAnnotationTypes({"me.bechberger.ebpf.annotations.bpf.BPF"})
@SupportedSourceVersion(SourceVersion.RELEASE_22)
public class Processor extends AbstractProcessor {

    private static final String BPF = "me.bechberger.ebpf.annotations.bpf.BPF";

    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment env) {
        this.processingEnv.getMessager().printNote("Processing BPF annotations");
        annotations.forEach(annotation -> {
            Set<? extends Element> elements = env.getElementsAnnotatedWith(annotation);
            if (annotation.getQualifiedName().toString().equals(BPF)) {
                elements.stream().filter(TypeElement.class::isInstance).map(TypeElement.class::cast).forEach(this::processBPFProgram);
            }
        });
        return true;
    }

    /**
     * Expects a class annotated with BPF:
     * <ul>
     *     <li>Class must extend BPFProgram</li>
     *     <li>Class must be abstract</li>
     *     <li>Class must contain a static field EBPF_PROGRAM of type String</li>
     *     <li>Field EBPF_PROGRAM must contain the eBPF program as a string literal or a path to valid EBPF program
     *     from the module path</li>
     *     <li>Can contain {@code @Type} annotated inner records</li>
     * </ul>
     */
    public void processBPFProgram(TypeElement typeElement) {
        System.out.println("Processing BPFProgram: " + typeElement.getQualifiedName());
        if (typeElement.getSuperclass() == null || !typeElement.getSuperclass().toString().equals("me.bechberger" +
                ".ebpf" + ".bpf.BPFProgram")) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with "
                    + "BPF but does not extend BPFProgram", typeElement);
            return;
        }
        if (!typeElement.getModifiers().contains(javax.lang.model.element.Modifier.ABSTRACT)) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with "
                    + "BPF but is not abstract", typeElement);
            return;
        }
        TypeProcessorResult typeProcessorResult;
        try {
            typeProcessorResult = new TypeProcessor(processingEnv).processBPFTypeRecords(typeElement);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        var combinedCode = combineEBPFProgram(typeElement, typeProcessorResult);
        if (combinedCode == null) {
            return;
        }
        byte[] bytes = compile(combinedCode);
        if (bytes == null) {
            return;
        }
        System.out.println("Compiled eBPF program " + bytes.length + " bytes");
        this.processingEnv.getMessager().printMessage(Diagnostic.Kind.OTHER, "Compiled eBPF program", typeElement);

        ImplName implName = typeToImplName(typeElement);

        TypeSpec typeSpec = createType(implName.className, typeElement.asType(), bytes,
                typeProcessorResult.fields(), combinedCode);
        try {
            var file = processingEnv.getFiler().createSourceFile(implName.fullyQualifiedClassName, typeElement);
            // delete file if it exists
            if (Files.exists(Path.of(file.toUri()))) {
                Files.delete(Path.of(file.toUri()));
            }
            JavaFile javaFile = JavaFile.builder(implName.packageName, typeSpec).build();
            try (var writer = file.openWriter()) {
                writer.write(javaFile.toString());
            }
            System.err.println("Wrote file " + file.toUri());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public record ImplName(String className, String fullyQualifiedClassName, String packageName) {}

    /** Creates the name of the implementing class */
    private static ImplName classNameToImplName(String packageName, String className) {
        if (packageName.isEmpty()) {
            return new ImplName(className + "Impl", className + "Impl", packageName);
        }
        var simpleName = className.replace(".", "$") + "Impl";
        return new ImplName(simpleName, packageName + "." + simpleName, packageName);
    }

    private static ImplName typeToImplName(TypeElement type) {
        // problem type might be nested
        List<String> classNameParts = new ArrayList<>();
        var t = type;
        classNameParts.add(t.getSimpleName().toString());
        while (t.getNestingKind() == NestingKind.MEMBER) {
            if (t.getEnclosingElement() instanceof TypeElement typeElement) {
                t = typeElement;
                classNameParts.addFirst(t.getSimpleName().toString());
            }
        }
        String qualifiedName = t.getQualifiedName().toString();
        return classNameToImplName(qualifiedName.substring(0, qualifiedName.length() - t.getSimpleName().length() - 1),
                String.join(".", classNameParts));
    }

    public static ImplName classToImplName(Class<?> klass) {
        if (klass.getPackageName().isEmpty()) {
            return classNameToImplName("", klass.getName());
        }
        return classNameToImplName(klass.getPackageName(), klass.getName().substring(klass.getPackageName().length() + 1));
    }

    /**
     * GZIP the bytecode and then turns it into a Base64 String
     */
    private static String gzipBase64Encode(byte[] byteCode) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
                gos.write(byteCode);
            }
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a class that implements the class of typeElement and overrides the getByteCode method to return the
     * compiled eBPF program, but store the compiled eBPF program as a base64 encoded string in a static final field
     *
     * @param name          the name of the class
     * @param baseType      the type of the class
     * @param byteCode      the compiled eBPF program
     * @param bpfTypeFields the {@code BPFStructType} fields of the class, related to the {@code @Type} annotated
     *                      inner records
     * @return the generated class
     */
    private TypeSpec createType(String name, TypeMirror baseType, byte[] byteCode, List<FieldSpec> bpfTypeFields,
                                CombinedCode code) {
        var spec =
                TypeSpec.classBuilder(name).superclass(baseType).addModifiers(Modifier.PUBLIC, Modifier.FINAL)
                        .addField(FieldSpec.builder(String.class, "BYTE_CODE", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
                                .addJavadoc("Base64 encoded and gzipped eBPF byte-code of the program\n{@snippet : \n" + sanitizeCodeForJavadoc(code.ebpfProgram) + "\n}")
                                .initializer("$S", gzipBase64Encode(byteCode)).build());
        // insert the spec fields
        bpfTypeFields.forEach(spec::addField);
        spec.addMethod(MethodSpec.methodBuilder("getByteCode")
                .addAnnotation(Override.class).addModifiers(Modifier.PUBLIC).returns(byte[].class)
                .addStatement("return me.bechberger.ebpf.bpf.Util.decodeGzippedBase64(BYTE_CODE)").build());
        // implement the constructor and set the map fields
        var constructor = MethodSpec.constructorBuilder().addModifiers(Modifier.PUBLIC);
        code.tp.mapDefinitions().forEach(m -> constructor.addStatement("$L", m.javaFieldInitializer()));
        spec.addMethod(constructor.build());
        return spec.build();
    }

    private String sanitizeCodeForJavadoc(String code) {
        return code.replace("*/", "* /").replace("/*", "/ *");
    }

    /**
     * The combined ebpf program code
     * @param ebpfProgram base ebpf program for the EBPF_PROGRAM variable
     * @param codeField field that contains the EBPF_PROGRAM
     * @param codeLineMapping line number in generated -> original line number
     */
    record CombinedCode(String ebpfProgram, VariableElement codeField, Map<Integer, Integer> codeLineMapping,
                        TypeProcessorResult tp, Set<Integer> generatedLines) {
    }

    private @Nullable CombinedCode combineEBPFProgram(TypeElement typeElement, TypeProcessorResult tpResult) {
        Optional<? extends Element> elem =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind().isField() && e.getSimpleName().toString().equals("EBPF_PROGRAM")).findFirst();
        // check that the class has a static field EBPF_PROGRAM of type String or Path
        if (elem.isEmpty()) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with "
                    + "BPF but does not contain a String field EBPF_PROGRAM which contains the field", typeElement);
            return null;
        }
        var element = (VariableElement) elem.get();
        // check that element is of correct type
        if (!element.asType().toString().equals("java.lang.String") && !element.asType().toString().equals("java.nio" +
                ".file.Path")) {
            this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() + " is not of type String or Path", typeElement);
            return null;
        }
        String ebpfProgram;
        if (element.getConstantValue() != null) {
            ebpfProgram = (String) element.getConstantValue();
        } else {
            this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() + " is not a constant string", typeElement);
            return null;
        }
        if (ebpfProgram.endsWith(".c") && ebpfProgram.split("\n").length == 1) {
            // a file path
            // check that the file exists and if so load it
            // if not, print an error
            try {
                Path p = getPath(ebpfProgram);
                if (p == null || !Files.exists(p)) {
                    this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() + " is a path to a file that does not exist, maybe pass base folder via -Aebpf.folder", typeElement);
                    return null;
                }
                try (var is = Files.newInputStream(p)) {
                    ebpfProgram = new String(is.readAllBytes());
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        this.processingEnv.getMessager().printNote("EBPF Program: " + ebpfProgram, typeElement);
        return combineEBPFProgram(typeElement, element, ebpfProgram, tpResult);
    }

    /** Combines the code */
    private @Nullable CombinedCode combineEBPFProgram(TypeElement outer, VariableElement field, String ebpfProgram, TypeProcessorResult tpResult) {
        Map<Integer, Integer> codeLineMapping = new HashMap<>(); // line number in generated -> original line number

        var lines = ebpfProgram.lines().toList();
        var lastInclude = IntStream.range(0, lines.size()).filter(i -> lines.get(i).startsWith("#include")).max().orElse(-1);
        var resultLines = new ArrayList<>(lines.subList(0, lastInclude + 1));
        if (lastInclude != -1) {
            IntStream.range(0, lastInclude + 1).forEach(i -> codeLineMapping.put(i, i));
            resultLines.add("");
        }

        Consumer<String> addLine = l -> resultLines.addAll(l.lines().toList());

        var filteredDefines = tpResult.defines().stream().filter(d -> {
            var tester = "#define " + d.name() + " ";
            return lines.stream().noneMatch(l -> l.startsWith(tester));
        }).toList();

        filteredDefines.stream().map(Define::toPrettyString).forEach(addLine);

        resultLines.add("");

        var license = lines.stream().filter(l -> l.matches(".*SEC *\\(\"license\"\\).*")).findFirst().orElse(null);
        if (tpResult.licenseDefinition() == null) {
            if (license == null) {
                this.processingEnv.getMessager().printWarning("No license defined in EBPF program", field);
            }
        } else {
            if (license != null) {
                this.processingEnv.getMessager().printError("License defined in EBPF program and via annotation", field);
                return null;
            }
        }

        // we already inserted the includes and the defines
        // now we insert the struct definitions
        tpResult.definingStatements().stream().map(CAST::toPrettyString).forEach(l -> {
            addLine.accept(l);
            resultLines.add("");
        });

        // and the defined maps
        tpResult.mapDefinitions().stream().map(m -> m.structDefinition().toPrettyString()).forEach(l -> {
            addLine.accept(l);
            resultLines.add("");
        });

        // now
        var afterIncludes = lines.subList(lastInclude + 1, lines.size());
        for (int i = 0; i < afterIncludes.size(); i++) {
            codeLineMapping.put(resultLines.size() + i, lastInclude + 1 + i);
        }
        resultLines.addAll(afterIncludes);
        if (license == null && tpResult.licenseDefinition() != null) {
            addLine.accept(tpResult.licenseDefinition().toStatement().toPrettyString());
        }
        var generatedLines = IntStream.range(0, resultLines.size()).filter(i -> !codeLineMapping.containsKey(i)).boxed().collect(Collectors.toSet());
        return new CombinedCode(String.join("\n", resultLines), field, codeLineMapping, tpResult, generatedLines);
    }

    private static String findNewestClangVersion() {
        for (int i = 12; i > 11; i--) {
            try {
                var name = i == 12 ? "clang" : "clang-" + i;
                var process = new ProcessBuilder(name, "--version").start();
                if (process.waitFor() == 0) {
                    return name;
                }
            } catch (IOException | InterruptedException e) {
                // ignore
            }
        }
        throw new RuntimeException("Could not find clang");
    }

    private static final String newestClang = findNewestClangVersion();
    private static Path includePath;

    /** Find the library include path */
    private static Path findIncludePath() {
        if (includePath == null) {
            // like /usr/include/aarch64-linux-gnu
            includePath = Path.of("/usr/include").resolve(System.getProperty("os.arch") + "-linux-gnu");
            if (!Files.exists(includePath)) {
                throw new RuntimeException("Could not find include path " + includePath);
            }
        }
        return includePath;
    }

    private byte[] compile(CombinedCode code) {
        if (dontCompile()) {
            System.out.println("EBPF program to compile:");
            System.out.println("-".repeat(10));
            System.out.println(code.ebpfProgram);
            return new byte[]{0};
        }
        // obtain the path to the vmlinux.h header file
        var vmlinuxHeader = getPathToVMLinuxHeader();
        if (vmlinuxHeader == null) {
            return null;
        }
        // compile the eBPF program
        // if the compilation fails, print an error
        // if the compilation succeeds, return the byte code
        System.out.println("Compiling eBPF program include path : " + findIncludePath());
        try {
            var tempFile = Files.createTempFile("ebpf", ".o");
            tempFile.toFile().deleteOnExit();
            var process = new ProcessBuilder(newestClang, "-O2", "-g", "-target", "bpf", "-c", "-o",
                    tempFile.toString(), "-I", vmlinuxHeader.getParent().toString(), "-x", "c", "-", "--sysroot=/", "-I" + findIncludePath()).redirectInput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.PIPE).start();
            process.getOutputStream().write(code.ebpfProgram.getBytes());
            process.getOutputStream().close();
            ByteArrayOutputStream error = new ByteArrayOutputStream();
            process.getErrorStream().transferTo(error);
            if (process.waitFor() != 0) {
                System.err.println("Could not compile eBPF program");
                var lines = code.ebpfProgram.split("\n");
                for (int i = 0; i < lines.length; i++) {
                    System.err.printf("%3d: %s\n", i + 1, lines[i]);
                }
                String errorString = error.toString();
                this.processingEnv.getMessager().printError("Could not compile eBPF program", code.codeField);
                this.processingEnv.getMessager().printError(errorString, code.codeField);
                printErrorMessages(code, errorString);
                throw new RuntimeException("Could not compile eBPF program");
            }
            return Files.readAllBytes(tempFile);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private void printErrorMessages(CombinedCode code, String errorString) {
        Path file = Paths.get(this.processingEnv.getElementUtils().getFileObjectOf(code.codeField).getName());
        Map<Integer, Line> lineMap = getLineMap(code);
        for (String line : errorString.split("\n")) {
            // example "<stdin>:5:58: error: expected ';' after expression"
            if (line.startsWith("<stdin>:")) {
                String[] parts = line.split(":", 4);
                int lineNumber = Integer.parseInt(parts[1]);
                int column = Integer.parseInt(parts[2]);
                String message = parts[3];
                Line l = lineMap.get(lineNumber);
                if (l != null) {
                    // format [ERROR] filename:[line,column] message
                    System.err.println(file + ":[" + l.line + "," + (l.start + column) + "] " + message);
                } else {
                    System.err.println(line);
                }
            } else {
                System.err.println(line);
            }
            var suggestions = suggestionsForMessage(line);
            if (!suggestions.isEmpty()) {
                System.out.println("Suggestions:");
                for (String suggestion : suggestions) {
                    System.out.println("  " + suggestion);
                }
            }
        }
    }

    private List<String> suggestionsForMessage(String message) {
        List<String> suggestions = new ArrayList<>();
        if (message.contains(" fatal error: 'bits/libc-header-start.h' file not found")) {
            suggestions.add("Try to install gcc-multilib");
        }
        if (message.contains(" fatal error: 'bpf_helpers.h' file not found")) {
            suggestions.add("Replace `#include 'bpf_helpers.h` with `#include <bpf/bpf_helpers.h>`");
        }
        return suggestions;
    }

    private record Line(int line, int start) {
    }

    private Map<Integer, Line> getLineMap(CombinedCode code) {
        Path file = Paths.get(this.processingEnv.getElementUtils().getFileObjectOf(code.codeField).getName());
        List<String> linesInGeneratedEBPFProgram = code.ebpfProgram.lines().toList();
        List<String> strippedLinesInGeneratedEBPFProgram = linesInGeneratedEBPFProgram.stream().map(String::strip).toList();
        List<String> linesInSourceFile;
        try {
            linesInSourceFile = Files.readAllLines(file);
        } catch (IOException e) {
            this.processingEnv.getMessager().printError("Could not read file " + file, code.codeField);
            return Map.of();
        }
        List<String> strippedLinesInSourceFile = linesInSourceFile.stream().map(String::strip).toList();
        Map<Integer, Line> generatedToSourceLine = new HashMap<>();

        int genIndex = 0;
        int sourceIndex = 0;
        boolean start = true;
        while (sourceIndex < strippedLinesInSourceFile.size() && genIndex < strippedLinesInGeneratedEBPFProgram.size()) {
            // omit clearly generated lines
            while (code.generatedLines.contains(genIndex)) {
                genIndex++;
            }
            if (genIndex >= strippedLinesInGeneratedEBPFProgram.size()) {
                break;
            }
            String strippedGenLine = strippedLinesInGeneratedEBPFProgram.get(genIndex);
            int newSourceIndex = strippedLinesInSourceFile.subList(sourceIndex, strippedLinesInSourceFile.size())
                    .indexOf(strippedGenLine) + sourceIndex;

            if (newSourceIndex == -1 + sourceIndex) {
                return Map.of();
            }

            boolean newStart = false;
            // check that there is no """ in between new and old source index
            for (int i = sourceIndex; i <= newSourceIndex && !start; i++) {
                if (strippedLinesInSourceFile.get(i).equals("\"\"\"")) {
                    genIndex = 0;
                    sourceIndex = i;
                    generatedToSourceLine.clear();
                    start = true;
                    newStart = true;
                    break;
                }
            }

            if (newStart) {
                continue;
            }
            sourceIndex = newSourceIndex;

            String sourceLine = linesInSourceFile.get(sourceIndex);
            String genLine = linesInGeneratedEBPFProgram.get(genIndex);
            int lineStart = sourceLine.indexOf(genLine);
            if (lineStart == -1) {
                return Map.of();
            }
            generatedToSourceLine.put(genIndex, new Line(sourceIndex, lineStart));
            start = false;
            sourceIndex++;
            genIndex++;
        }

        return generatedToSourceLine;
    }

    private @Nullable Optional<Path> obtainedPathToVMLinuxHeader = null;

    private @Nullable Path getPathToVMLinuxHeader() {
        if (obtainedPathToVMLinuxHeader == null) {
            obtainedPathToVMLinuxHeader = Optional.ofNullable(obtainPathToVMLinuxHeader());
        }
        return obtainedPathToVMLinuxHeader.orElse(null);
    }

    private Path obtainPathToVMLinuxHeader() {
        // obtain the path to the vmlinux.h header file
        // if it is not found, print an error
        try {
            System.out.println("Obtaining vmlinux.h header file");
            // first check in the module path
            Path vmlinuxHeader = getPath("vmlinux.h");
            if (vmlinuxHeader != null && Files.exists(vmlinuxHeader)) {
                return vmlinuxHeader;
            }
            // else run bpftool btf dump file /sys/kernel/btf/vmlinux format c
            // save output to a temp file and return the path to the temp file
            var tempDirectory = Files.createTempDirectory("vmlinux");
            tempDirectory.toFile().deleteOnExit();
            var tempFile = tempDirectory.resolve("vmlinux.h");
            var errorFile = tempDirectory.resolve("error.txt");
            var process = new ProcessBuilder("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format",
                    "c").redirectOutput(tempFile.toFile()).redirectError(errorFile.toFile()).start();
            if (process.waitFor() != 0) {
                this.processingEnv.getMessager().printError("Could not obtain vmlinux.h header file via 'bpftool btf "
                        + "dump file /sys/kernel/btf/vmlinux format c'\n" + Files.readString(errorFile), null);
                return null;
            }
            return tempFile;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public @Nullable Path getEBPFFolder() {
        String p = processingEnv.getOptions().getOrDefault("ebpf.folder", null);
        if (p == null) {
            String val = System.getenv("EBPF_FOLDER");
            return val == null ? null : Path.of(val);
        }
        return Path.of(p);
    }

    private @Nullable Path getPath(String name) {
        if (name.startsWith("/") || name.startsWith("./") || name.startsWith("../")) {
            return Path.of(name);
        }
        if (name.startsWith("~/")) {
            return Path.of(System.getProperty("user.home"), name.substring(2));
        }
        return getEBPFFolder() == null ? null : getEBPFFolder().resolve(name);
    }

    private boolean dontCompile() {
        return "true".equals(System.getenv("EBPF_DONT_COMPILE"));
    }
}