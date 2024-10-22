package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.*;
import me.bechberger.cast.CAST;
import me.bechberger.cast.CAST.Statement.Define;
import me.bechberger.cast.CAST.Statement.Include;
import me.bechberger.ebpf.annotations.bpf.BPFImpl;
import me.bechberger.ebpf.bpf.processor.TypeProcessor.GlobalVariableDefinition;
import me.bechberger.ebpf.bpf.processor.TypeProcessor.TypeProcessorResult;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.*;
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
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.zip.GZIPOutputStream;

/**
 * Annotation compiler that processes classes annotated with {@code @BPF}.
 * <p>
 * The compiler compiles the eBPF program and takes care of {@code @Type} inner types.
 */
@SupportedAnnotationTypes({"me.bechberger.ebpf.annotations.bpf.BPF"})
@SupportedSourceVersion(SourceVersion.RELEASE_22)
public class Processor extends AbstractProcessor {

    private static final String BPF = "me.bechberger.ebpf.annotations.bpf.BPF";
    private final CompilationCache cache = new CompilationCache(Paths.get("."));

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
            if (typeProcessorResult == null) {
                return;
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        var combinedCode = combineEBPFProgram(typeElement, typeProcessorResult, false);
        if (combinedCode == null) {
            return;
        }
        // TODO make configurable or throw out
        byte[] bytes = new byte[0];//compile(combinedCode, Path.of(this.processingEnv.getElementUtils().getFileObjectOf(typeElement).toUri().getPath()));
        if (bytes == null) {
            return;
        }
        this.processingEnv.getMessager().printMessage(Diagnostic.Kind.OTHER, "Compiled eBPF program", typeElement);

        ImplName implName = typeToImplName(typeElement);

        TypeSpec typeSpec = createType(implName.className, typeElement.asType(), bytes,
                typeProcessorResult.fields(), combinedCode, typeProcessorResult.globalVariableDefinitions(),
                typeProcessorResult.additions());
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

    public record CompileResult(byte[] byteCode) {
        public String encode() {
            return gzipBase64Encode(byteCode);
        }

        public byte[] gzip() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gos = new GZIPOutputStream(baos)) {
                gos.write(byteCode);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return baos.toByteArray();
        }
    }

    public static CompileResult compileAndEncode(ProcessingEnvironment env, String code, Path file) {
        var processor = new Processor();
        processor.processingEnv = env;
        return new CompileResult(processor.compile(new CombinedCode(code, null, null, List.of()), file));
    }

    /**
     * Create a class that implements the class of typeElement and overrides the getByteCode method to return the
     * compiled eBPF program, but store the compiled eBPF program as a base64 encoded string in a static final field
     *
     * @param name                      the name of the class
     * @param baseType                  the type of the class
     * @param byteCode                  the compiled eBPF program
     * @param bpfTypeFields             the {@code BPFStructType} fields of the class, related to the {@code @Type} annotated
     *                                  inner records
     * @param globalVariableDefinitions
     * @return the generated class
     */
    private TypeSpec createType(String name, TypeMirror baseType, byte[] byteCode, List<FieldSpec> bpfTypeFields,
                                CombinedCode code, List<GlobalVariableDefinition> globalVariableDefinitions,
                                TypeProcessor.InterfaceAdditions additions) {
        var suppressWarnings = AnnotationSpec.builder(SuppressWarnings.class).addMember("value", "{\"unchecked\", \"rawtypes\"}").build();

        var spec =
                TypeSpec.classBuilder(name)
                        .addAnnotation(suppressWarnings).superclass(baseType)
                        .addAnnotation(AnnotationSpec.builder(BPFImpl.class)
                                .addMember("before", "\"\"\"\n" + String.join("\n", additions.before()).replace("\\", "\\\\") + "\n\"\"\"")
                                .addMember("after", "\"\"\"\n" + String.join("\n", additions.after()).replace("\\", "\\\\") + "\n\"\"\"").build())
                        .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
                        .addField(FieldSpec.builder(String.class, "BYTE_CODE", Modifier.PRIVATE, Modifier.STATIC, Modifier.FINAL)
                                .addJavadoc("Base64 encoded and gzipped eBPF byte-code of the program\n{@snippet : \n" + sanitizeCodeForJavadoc(code.ebpfProgram) + "\n}")
                                .initializer("$L", createStringExpression(gzipBase64Encode(byteCode))).build())
                        .addField(FieldSpec.builder(String.class, "CODE", Modifier.PUBLIC, Modifier.STATIC, Modifier.FINAL)
                                .initializer("$S", code.ebpfProgram).build());
        bpfTypeFields.forEach(spec::addField);
        spec.addMethod(MethodSpec.methodBuilder("getByteCodeBytesStatic")
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC).returns(String.class)
                .addStatement("return BYTE_CODE + \"\"").build());
        spec.addMethod(MethodSpec.methodBuilder("getByteCode")
                .addModifiers(Modifier.PUBLIC).returns(byte[].class)
                                .beginControlFlow("if (getByteCodeResourceName().isEmpty())")
                                .addStatement("return me.bechberger.ebpf.bpf.Util.decodeGzippedBase64(getByteCodeBytesStatic())")
                                .nextControlFlow("else")
                                .addStatement("return me.bechberger.ebpf.bpf.Util.loadGzippedResource($L.class, getByteCodeResourceName())", name)
                                .endControlFlow()
                                .build());
        spec.addMethod(MethodSpec.methodBuilder("getByteCodeResourceName")
                .addModifiers(Modifier.PUBLIC).returns(String.class)
                .addStatement("return \"\"").build());
        spec.addMethod(MethodSpec.methodBuilder("getCodeStatic")
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC).returns(String.class)
                .addStatement("return CODE").build());
        spec.addMethod(MethodSpec.methodBuilder("getCode")
                .addAnnotation(Override.class).addModifiers(Modifier.PUBLIC).returns(String.class)
                .addStatement("return getCodeStatic()").build());
        spec.addMethod(MethodSpec.methodBuilder("getAutoAttachablePrograms").addAnnotation(Override.class).addModifiers(Modifier.PUBLIC)
                .returns(ParameterizedTypeName.get(ClassName.get(List.class), ClassName.get(String.class)))
                .addStatement("return java.util.List.of($L)", code.autoAttachablePrograms.stream().map(s -> "\"" + s + "\"").collect(Collectors.joining(", "))).build());
        // implement the constructor and set the map fields
        var constructor = MethodSpec.constructorBuilder().addModifiers(Modifier.PUBLIC);
        code.tp.mapDefinitions().forEach(m -> {
            constructor.addStatement("$L", m.javaFieldInitializer());
        });
        spec.addMethod(constructor.build());
        if (!globalVariableDefinitions.isEmpty()) {
            spec.addMethod(addGlobalVariableDefinitions(MethodSpec.methodBuilder("initGlobals")
                    .addAnnotation(Override.class).addModifiers(Modifier.PUBLIC).returns(TypeName.VOID), globalVariableDefinitions).build());
        }
        return spec.build();
    }

    private String createStringExpression(String s) {
        // split the string into 2 << 16 character parts, as this is the maximum length of a string literal
        var parts = new ArrayList<String>();
        for (int i = 0; i < s.length(); i += 2 << 16) {
            parts.add(s.substring(i, Math.min(i + (2 << 16), s.length())));
        }
        return parts.stream().map(p -> "\"" + p + "\"").collect(Collectors.joining(" + \"\\n\" + "));
    }

    /*

        public record GlobabVariableInitInfo<T>(GlobalVariable<T> variable, String name, BPFType<T> type) {
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        public void initGlobals(List<GlobabVariableInitInfo<?>> globalVariables) {
     */
    private MethodSpec.Builder addGlobalVariableDefinitions(MethodSpec.Builder spec, List<GlobalVariableDefinition> globalVariableDefinitions) {
        if (globalVariableDefinitions.isEmpty()) {
            return spec;
        }

        var globalVariablesType = ClassName.get("me.bechberger.ebpf.bpf", "GlobalVariable", "Globals");

        spec.addStatement("$T globalVariables = $T.forProgram(this)", globalVariablesType, globalVariablesType)
                .addStatement("globalVariables.initGlobals(java.util.List.of($L))", globalVariableDefinitions.stream().map(this::createGlobalVariableInitInfoExpression).collect(Collectors.joining(", ")));
        return spec;
    }

    private String createGlobalVariableInitInfoExpression(GlobalVariableDefinition g) {
        return "new me.bechberger.ebpf.bpf.GlobalVariable.GlobalVariableInitInfo<>(this." + g.name() + ", \"" + g.name() + "\", " + g.typeField() + ")";
    }

    private String sanitizeCodeForJavadoc(String code) {
        return code.replace("*/", "* /").replace("/*", "/ *");
    }

    /**
     * The combined ebpf program code
     * @param ebpfProgram base ebpf program for the EBPF_PROGRAM variable
     * @param codeField field that contains the EBPF_PROGRAM
     */
    record CombinedCode(String ebpfProgram, VariableElement codeField,
                        TypeProcessorResult tp, List<String> autoAttachablePrograms) {
    }

    private @Nullable CombinedCode combineEBPFProgram(TypeElement typeElement, TypeProcessorResult tpResult, boolean addAdditions) {
        Optional<? extends Element> elem =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind().isField() && e.getSimpleName().toString().equals("EBPF_PROGRAM")).findFirst();
        // check that the class has a static field EBPF_PROGRAM of type String or Path
        if (elem.isEmpty()) {
           // this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with "
            //        + "BPF but does not contain a String field EBPF_PROGRAM which contains the field", typeElement);
            return combineEBPFProgram(typeElement, null, "", tpResult, addAdditions);
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
        return combineEBPFProgram(typeElement, element, ebpfProgram, tpResult, addAdditions);
    }

    private List<String> findAutoAttachablePrograms(String ebpfProgram) {
        /*
        Find names with patterns like: SEC("...")
        ... (but without {) BPF_PROG(NAME...) {

        or like: SEC("...") ... (but without {) NAME(...) {
        via regexp
         */
        String ebpfProgramWithoutMultipleSpacesOrNewlines = ebpfProgram.replaceAll("[\\s]+", " ");
        List<String> autoAttachablePrograms = new ArrayList<>();
        for (var part : ebpfProgramWithoutMultipleSpacesOrNewlines.split("SEC\\s*\\(\"[^\"]*\"")) {
            if (!part.startsWith(")")) {
                continue;
            }
            part = part.substring(1);
            var matcher = Pattern.compile("([a-zA-Z0-9_]+)\\s?\\(").matcher(part);
            if (matcher.find()) {
                String match = matcher.group(1);
                if (SUPPORTED_BPF_PROG_MACROS.contains(match)) {
                    // take the first word after the macro
                    var nameMatcher = Pattern.compile("([a-zA-Z0-9_]+)").matcher(part.substring(matcher.end()));
                    if (nameMatcher.find()) {
                        autoAttachablePrograms.add(nameMatcher.group(1));
                    }
                } else {
                    autoAttachablePrograms.add(match);
                }
            }
        }
        return autoAttachablePrograms;
    }

    private static final Set<String> SUPPORTED_BPF_PROG_MACROS = Set.of("BPF_PROG");

    /** Combines the code */
    private @Nullable Processor.CombinedCode combineEBPFProgram(TypeElement outer, VariableElement field, String ebpfProgram, TypeProcessorResult tpResult, boolean addAdditions) {
        var unstrippedLines = ebpfProgram.lines().toList();
        var lastInclude = IntStream.range(0, unstrippedLines.size()).filter(i -> unstrippedLines.get(i).contains("#include")).max().orElse(-1);
        List<String> lines;
        if (lastInclude != -1) {
            var ws = unstrippedLines.get(lastInclude).split("#include")[0];
            lines = unstrippedLines.stream().map(l -> l.startsWith(ws) ? l.substring(ws.length()) : l).toList();
        } else {
            lines = unstrippedLines;
        }
        var resultLines = new ArrayList<>(lines.subList(0, lastInclude + 1));

        // we add the includes
        tpResult.additions().includes().stream().map(Include::new).filter(include -> !include.isAlreadyPresent(resultLines)).forEach(include -> {
            resultLines.add(include.toPrettyString());
        });

        Consumer<List<?>> addEmptyLineIfNeeded = (list) -> {
            if (!list.isEmpty() && !resultLines.isEmpty() && !resultLines.getLast().isBlank()) {
                resultLines.add("");
            }
        };

        Consumer<String> addLine = l -> resultLines.addAll(l.lines().toList());

        // add the before lines
        if (addAdditions) {
            addEmptyLineIfNeeded.accept(tpResult.additions().before());
            tpResult.additions().before().forEach(addLine);
        }

        var filteredDefines = tpResult.defines().stream().filter(d -> {
            var tester = "#define " + d.name() + " ";
            return lines.stream().noneMatch(l -> l.startsWith(tester));
        }).toList();

        addEmptyLineIfNeeded.accept(filteredDefines);

        filteredDefines.stream().map(Define::toPrettyString).forEach(addLine);
        if (!filteredDefines.isEmpty()) {
            resultLines.add("");
        }

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
        addEmptyLineIfNeeded.accept(tpResult.definingStatements());
        tpResult.definingStatements().stream().map(CAST::toPrettyString).forEach(l -> {
            addLine.accept(l);
            resultLines.add("");
        });

        // and the defined maps
        addEmptyLineIfNeeded.accept(tpResult.mapDefinitions());
        tpResult.mapDefinitions().stream().map(m -> m.structDefinition().toPrettyString()).forEach(l -> {
            addLine.accept(l);
            resultLines.add("");
        });

        // and the global variables
        addEmptyLineIfNeeded.accept(tpResult.globalVariableDefinitions());
        tpResult.globalVariableDefinitions().forEach(v -> {
            String line = v.globalVariable().toPrettyString();
            addLine.accept(line);
            resultLines.add("");
        });

        // now
        var afterIncludes = lines.subList(lastInclude + 1, lines.size());
        if (afterIncludes.isEmpty() || !afterIncludes.getFirst().isBlank()) {
            addEmptyLineIfNeeded.accept(afterIncludes);
        }
        resultLines.addAll(afterIncludes);

        // add the after lines
        if (addAdditions) {
            addEmptyLineIfNeeded.accept(tpResult.additions().after());
            tpResult.additions().after().forEach(addLine);
        }

        if (license == null && tpResult.licenseDefinition() != null) {
            addEmptyLineIfNeeded.accept(List.of(""));
            addLine.accept(tpResult.licenseDefinition().toStatement().toPrettyString());
        }

        // remove end new lines
        while (!resultLines.isEmpty() && resultLines.getLast().isBlank()) {
            resultLines.removeLast();
        }

        List<String> autoAttachablePrograms = findAutoAttachablePrograms(ebpfProgram);
        return new CombinedCode(String.join("\n", resultLines), field, tpResult, autoAttachablePrograms);
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
                includePath = Path.of("/usr/include/linux");
                if (!Files.exists(includePath)) {
                    throw new RuntimeException("Could not find include path " + includePath);
                }
            }
        }
        return includePath;
    }

    private static String getArch() {
        var arch = System.getProperty("os.arch");
        if (arch.equals("amd64")) {
            return "x86";
        }
        if (arch.equals("aarch64")) {
            return "arm64";
        }
        return arch;
    }

    private byte[] compile(CombinedCode code, Path ebpfFile) {
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
        this.processingEnv.getMessager().printNote("Compiling eBPF program include path : " + findIncludePath());
        var cached = cache.getCached(code.ebpfProgram + "|" + getArch());
        if (cached != null) {
            return cached;
        }
        try {
            var tempFile = Files.createTempFile("ebpf", ".o");
            tempFile.toFile().deleteOnExit();
            List<String> command = List.of(newestClang, "-O2", "-g", "-std=gnu2y",  "-target", "bpf", "-c", "-o",
                    tempFile.toString(), "-I", vmlinuxHeader.getParent().toString(),
                    "-D__TARGET_ARCH_" + getArch(), "-Wno-parentheses-equality", "-Wno-unused-value", "-Wreturn-type",
                    "-Wno-incompatible-pointer-types-discards-qualifiers",
                    "-x", "c", "-", "--sysroot=/", "-I" + findIncludePath());
            var process = new ProcessBuilder(command).redirectInput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.PIPE).start();
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
                this.processingEnv.getMessager().printError("Could not compile eBPF program via " +
                        String.join(" ", command), code.codeField);
                printErrorMessages(code, errorString, ebpfFile);
                return new byte[0];
                //throw new RuntimeException("Could not compile eBPF program");
            }
            var bytes = Files.readAllBytes(tempFile);
            cache.cache(code.ebpfProgram + "|" + getArch(), bytes);
            return bytes;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private void printErrorMessages(CombinedCode code, String errorString, Path ebpfFile) {
        var processor = CompilerErrorProcessor.fromClangOutput(errorString, ebpfFile);
        var colorize = Objects.equals(System.getenv("EBPF_COLORIZE"),"true");
        var out = processor.toPrettyString(colorize);
        if (ebpfFile.toString().endsWith(".c")) {
            this.processingEnv.getMessager().printError(out);
        } else {
            System.err.println(out);
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
            // first check in the module path
            Path vmlinuxHeader = getPath("vmlinux.h");
            if (vmlinuxHeader != null && Files.exists(vmlinuxHeader)) {
                return vmlinuxHeader;
            }
            // else run bpftool btf dump file /sys/kernel/btf/vmlinux format c
            // save output to a temp file and return the path to the temp file
            var cacheFolder = cache.getCacheFolder();
            var vmLinuxFile = cacheFolder.resolve("vmlinux.h");
            if (Files.exists(vmLinuxFile)) {
                return vmLinuxFile;
            }
            var errorFile = cacheFolder.resolve("vmlinux_error.txt");
            var process = new ProcessBuilder("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format",
                    "c").redirectOutput(vmLinuxFile.toFile()).redirectError(errorFile.toFile()).start();
            if (process.waitFor() != 0) {
                throw new UnsupportedOperationException("Could not obtain vmlinux.h header file via 'bpftool btf "
                        + "dump file /sys/kernel/btf/vmlinux format c'" + Files.readString(errorFile));
            } else {
                Files.delete(errorFile);
            }
            // comment lines
            //  typedef _Bool bool;
            //  enum {
            //	false = 0,
            //	true = 1,
            //  };
            String content = Files.readString(vmLinuxFile);
            content = content.replace("typedef _Bool bool;", "// typedef _Bool bool")
                    .replaceAll("""
                                enum \\{
                                \\s+false = 0,
                                \\s+true = 1,
                                };
                                """, """
                                // enum {
                                //	false = 0,
                                //	true = 1,
                                // };
                                """);
            Files.writeString(vmLinuxFile, content);
            return vmLinuxFile;
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