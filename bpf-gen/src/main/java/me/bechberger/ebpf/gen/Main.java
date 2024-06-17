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
 * Usage: java ... <folder> <helper-json-file> [<package name, default: me.bechberger.ebpf.runtime>]
 */
@Command(name = "bpf-gen", mixinStandardHelpOptions = true,
        description = "Generates eBPF code from Java classes")
public class Main implements Runnable {

    // create with picocli
    @Parameters(index = "0", description = "Folder to emit the Java class too")
    private Path folder;

    @Parameters(index = "1", description = "JSON file containing the helper function descriptions")
    private Path helperJsonFile;

    @Parameters(index = "2", description = "Package name of the generated Java class", defaultValue = "me.bechberger" +
            ".ebpf.runtime")
    private final String packageName = "me.bechberger.ebpf.runtime";

    @Option(names = {"-v", "--verbose"}, description = "Be verbose")
    private final boolean verbose = false;

    @Override
    public void run() {
        if (verbose) {
            Logger.getGlobal().setLevel(java.util.logging.Level.ALL);
        }
        try {
            var syscalls = SystemCallUtil.parse();
            for (var syscall : syscalls) {
                System.out.printf("Syscall %s: %s %n", syscall.name(), syscall.definition());
                System.out.println(syscall.funcDefinition().toMethodSpec(new Generator(packageName)));
            }
            /*
            var gen = new Generator(packageName);
            gen.process();
            var res = gen.storeInFolder(folder);
            System.out.printf("Generated code for %d BTF types (%.2f %% of all types)%n", res.supportedTypes(), 100.0
             * res.supportedTypes() / (res.supportedTypes() + res.unsupportedTypes()));
            var helperProcessor = new HelperJSONProcessor(packageName);
            helperProcessor.process(helperJsonFile);
            helperProcessor.storeInFolder(folder);*/
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