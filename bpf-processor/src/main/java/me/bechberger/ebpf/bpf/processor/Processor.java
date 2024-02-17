package me.bechberger.ebpf.bpf.processor;

import com.squareup.javapoet.FieldSpec;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.TypeSpec;
import org.jetbrains.annotations.Nullable;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.annotation.processing.SupportedAnnotationTypes;
import javax.annotation.processing.SupportedSourceVersion;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@SupportedAnnotationTypes("me.bechberger.ebpf.annotations.bpf.BPF")
@SupportedSourceVersion(SourceVersion.RELEASE_21)
public class Processor extends AbstractProcessor {

    public boolean process(Set<? extends TypeElement> annotations,
                           RoundEnvironment env) {
        this.processingEnv.getMessager().printNote("Processing BPF annotations");
        annotations.forEach(annotation -> {
                    Set<? extends Element> elements = env.getElementsAnnotatedWith(annotation);
                    if (annotation.getQualifiedName().toString().equals("me.bechberger.ebpf.annotations.bpf.BPF")) {
                        elements.stream()
                                .filter(TypeElement.class::isInstance)
                                .map(TypeElement.class::cast).forEach(this::processBPFProgram);
                    }
                }
        );
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
     * </ul>
     */
    public void processBPFProgram(TypeElement typeElement) {
        System.out.println("Processing BPFProgram: " + typeElement.getQualifiedName());
        if (typeElement.getSuperclass() == null || !typeElement.getSuperclass().toString().equals("me.bechberger.ebpf" +
                ".bpf.BPFProgram")) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with " +
                    "BPF but does not extend BPFProgram", typeElement);
            return;
        }
        if (!typeElement.getModifiers().contains(javax.lang.model.element.Modifier.ABSTRACT)) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with " +
                    "BPF but is not abstract", typeElement);
            return;
        }
        byte[] bytes = compileProgram(typeElement);
        System.out.println("Compiled eBPF program " + bytes.length + " bytes");
        // create class that implement the class of typeElement and override the getByteCode method to return the
        // compiled eBPF program, but store this ebpf program as a base64 string
        if (bytes == null) {
            return;
        }
        this.processingEnv.getMessager().printMessage(Diagnostic.Kind.OTHER, "Compiled eBPF program",
                typeElement);

        String pkg = typeElement.getQualifiedName().toString();
        pkg = pkg.substring(0, pkg.lastIndexOf('.')).toLowerCase();
        String name = typeElement.getSimpleName().toString() + "Impl";
        TypeSpec typeSpec = createType(typeElement.getSimpleName() + "Impl", typeElement.asType(), bytes);
        try {
            var file = processingEnv.getFiler().createSourceFile(pkg + "." + name,
                    typeElement);
            // delete file if it exists
            if (Files.exists(Path.of(file.toUri()))) {
                Files.delete(Path.of(file.toUri()));
            }
            JavaFile javaFile = JavaFile.builder(pkg, typeSpec).build();
            try (var writer = file.openWriter()) {
                writer.write(javaFile.toString());
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a class that implements the class of typeElement and overrides the getByteCode method to return the
     * compiled eBPF program, but store the compiled eBPF program as a base64 encoded string in a static final field
     */
    private TypeSpec createType(String name, TypeMirror baseType, byte[] byteCode) {
        return TypeSpec.classBuilder(name)
                .superclass(baseType)
                .addModifiers(Modifier.PUBLIC, Modifier.FINAL)
                .addField(FieldSpec.builder(String.class, "BYTE_CODE", Modifier.PRIVATE, Modifier.STATIC,
                        Modifier.FINAL).addJavadoc("Base64 encoded eBPF byte-code").initializer("$S",
                        Base64.getEncoder().encodeToString(byteCode)).build())
                .addMethod(MethodSpec.methodBuilder("getByteCode")
                        .addAnnotation(Override.class)
                        .addModifiers(Modifier.PUBLIC)
                        .returns(byte[].class)
                        .addStatement("return $T.getDecoder().decode(BYTE_CODE)", Base64.class)
                        .build())
                .build();
    }

    private byte[] compileProgram(TypeElement typeElement) {
        Optional<? extends Element> elem =
                typeElement.getEnclosedElements().stream().filter(e -> e.getKind().isField() && e.getSimpleName().toString().equals
                        ("EBPF_PROGRAM")).findFirst();
        // check that the class has a static field EBPF_PROGRAM of type String or Path
        if (elem.isEmpty()) {
            this.processingEnv.getMessager().printError("Class " + typeElement.getSimpleName() + " is annotated with " +
                    "BPF but does not contain a String field EBPF_PROGRAM which contains the field", typeElement);
            return null;
        }
        var element = (VariableElement)elem.get();
        // check that element is of correct type
        if (!element.asType().toString().equals("java.lang.String") && !element.asType().toString().equals("java.nio.file.Path")) {
            this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() +
                    " is not of type String or Path", typeElement);
            return null;
        }
        String ebpfProgram;
        if (element.getConstantValue() != null) {
            ebpfProgram = (String) element.getConstantValue();
        } else {
            this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() +
                    " is not a constant string", typeElement);
            return null;
        }
        if (ebpfProgram.endsWith(".c") && ebpfProgram.split("\n").length == 1) {
            // a file path
            // check that the file exists and if so load it
            // if not, print an error
            try {
                Path p = getPath(ebpfProgram);
                if (p == null || !Files.exists(p)) {
                    this.processingEnv.getMessager().printError("Field EBPF_PROGRAM in class " + typeElement.getSimpleName() +
                            " is a path to a file that does not exist, maybe pass base folder via -Aebpf.folder",
                            typeElement);
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
        return compile(ebpfProgram, element);
    }

    private byte[] compile(String ebpfProgram, VariableElement element) {
        // obtain the path to the vmlinux.h header file
        var vmlinuxHeader = obtainPathToVMLinuxHeader();
        if (vmlinuxHeader == null) {
            return null;
        }
        // compile the eBPF program
        // if the compilation fails, print an error
        // if the compilation succeeds, return the byte code
        try {
            var tempFile = Files.createTempFile("ebpf", ".o");
            tempFile.toFile().deleteOnExit();
            var process = new ProcessBuilder("clang", "-O2", "-target", "bpf", "-c", "-o", tempFile.toString(),
                    "-I", vmlinuxHeader.getParent().toString(), "-x", "c", "-",
                    "--sysroot=/").redirectInput(ProcessBuilder.Redirect.PIPE).redirectError(ProcessBuilder.Redirect.PIPE)
                    .start();
            process.getOutputStream().write(ebpfProgram.getBytes());
            process.getOutputStream().close();
            ByteArrayOutputStream error = new ByteArrayOutputStream();
            process.getErrorStream().transferTo(error);
            if (process.waitFor() != 0) {
                System.err.println("Could not compile eBPF program");

                String errorString = error.toString();
                this.processingEnv.getMessager().printError("Could not compile eBPF program", element);
                this.processingEnv.getMessager().printError(errorString, element);
                printErrorMessages(ebpfProgram, errorString, element);
                throw new RuntimeException("Could not compile eBPF program");
            }
            return Files.readAllBytes(tempFile);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private void printErrorMessages(String ebpfProgram, String errorString, VariableElement element) {
        Path file = Paths.get(this.processingEnv.getElementUtils().getFileObjectOf(element).getName());
        Map<Integer, Line> lineMap = getLineMap(ebpfProgram, element);
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
                    System.err.println(file.getFileName() + ":[" + l.line + "," + (l.start + column) + "] " + message);
                } else {
                    System.err.println(line);
                }
            } else {
                System.err.println(line);
            }
        }
        // [ERROR] /home/i560383/code/experiments/ebpf/hello/bpf-processor/src/main/java/me/bechberger/ebpf/bpf/processor/Processor.java:[256,24] cannot find symbol
    }

    private record Line(int line, int start) {}

    private Map<Integer, Line> getLineMap(String ebpfProgram, VariableElement element) {
        Path file = Paths.get(this.processingEnv.getElementUtils().getFileObjectOf(element).getName());
        List<String> linesInEBPFProgram = ebpfProgram.lines().toList();
        List<String> linesInFile;
        try {
            linesInFile = Files.readAllLines(file);
        } catch (IOException e) {
            this.processingEnv.getMessager().printError("Could not read file " + file, element);
            return Map.of();
        }
        // find line that (excluding whitespace) matches the start of the line in the ebpf program
        Map<Integer, Line> lineMap = new HashMap<>();
        int line = 0;
        for (int i = 0; i < linesInEBPFProgram.size(); i++) {
            String lineInEBPFProgram = linesInEBPFProgram.get(i);
            String lineInEBPFProgramTrimmed = lineInEBPFProgram.strip().replace("\\", "");
            while (line < linesInFile.size()) {
                String lineInFile = linesInFile.get(line);
                String lineInFileTrimmed = lineInFile.strip().replace("\\", "");
                if (lineInFileTrimmed.startsWith(lineInEBPFProgramTrimmed)) {
                    lineMap.put(i, new Line(line, lineInFile.indexOf(lineInEBPFProgram)));
                    line++;
                    break;
                }
                line++;
            }
            if (lineMap.size() == linesInEBPFProgram.size()) {
                return lineMap;
            }
        }
        return Map.of();
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
            var tempFile = Files.createTempFile("vmlinux", ".h");
            tempFile.toFile().deleteOnExit();
            var process = new ProcessBuilder("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
                    .redirectOutput(tempFile.toFile())
                    .start();
            if (process.waitFor() != 0) {
                this.processingEnv.getMessager().printError("Could not obtain vmlinux.h header file via 'bpftool btf " +
                        "dump file /sys/kernel/btf/vmlinux format c'", null);
                return null;
            }
            return tempFile;
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public @Nullable Path getEBPFFolder() {
        String p = processingEnv.getOptions().getOrDefault("ebpf.folder", null);
        return p == null ? null : Path.of(p);
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
}
