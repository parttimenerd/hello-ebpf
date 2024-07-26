/* var tempDirectory = Files.createTempDirectory("vmlinux");
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
            return tempFile;*/

package me.bechberger.ebpf.gen;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Usage: java ... <folder> <helper-json-file> [...]
 */
@Command(name = "bpf-gen", mixinStandardHelpOptions = true, description = "Generates eBPF code from Java classes")
public class Main implements Runnable {

    // create with picocli
    @Parameters(index = "0", description = "Folder to emit the Java class too")
    private Path folder;

    @Parameters(index = "1", description = "JSON file containing the helper function descriptions")
    private Path helperJsonFile;

    @Parameters(index = "2", description = "Package name of the generated Java classes for the runtime",
            defaultValue = "me.bechberger" + ".ebpf.runtime")
    private String runtimePackageName = "me.bechberger.ebpf.runtime";

    @Parameters(index = "3", description = "Package name of the generated Java class for the helpers", defaultValue =
            "me.bechberger" + ".ebpf.runtime.helpers")
    private String helperPackageName = "me.bechberger.ebpf.runtime.helpers";

    @Parameters(index = "4", description = "Package name of the generated interfaces", defaultValue =
            "me.bechberger" + ".ebpf.runtime.interfaces")
    private String interfacePackageName = "me.bechberger.ebpf.runtime.interfaces";

    @Option(names = {"-v", "--verbose"}, description = "Be verbose")
    private boolean verbose = false;

    @Override
    public void run() {
        if (verbose) {
            Logger.getGlobal().setLevel(java.util.logging.Level.ALL);
        }
        try {
            var gen = new Generator(runtimePackageName);
            gen.process();
            var generated = gen.generateBPFRuntimeJavaFiles();
            generated.storeInFolder(folder);
            var translator = gen.createNameTranslator();
            var helperProcessor = new HelperJSONProcessor(helperPackageName, translator);
            helperProcessor.process(helperJsonFile);
            helperProcessor.createClass(generated).storeInFolder(folder);
            var syscalls = SystemCallProcessor.parse(translator);
            SystemCallProcessor.createSystemClassInterface(gen, interfacePackageName, syscalls, generated).storeInFolder(folder);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        // use picocli + help if no args
        if (args.length == 0) {
            new CommandLine(new Main()).execute("--help");
            return;
        }
        new CommandLine(new Main()).execute(args);
    }
}