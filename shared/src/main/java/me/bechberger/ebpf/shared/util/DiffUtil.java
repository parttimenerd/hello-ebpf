package me.bechberger.ebpf.shared.util;

import java.nio.file.Files;
import java.nio.file.Path;

/** Calls the diff command to create diffs between files */
public class DiffUtil {

    public static String diff(String left, String right) {
        try {
            Path leftFile = Files.createTempFile("left", ".txt");
            Path rightFile = Files.createTempFile("right", ".txt");
            Files.writeString(leftFile, left);
            Files.writeString(rightFile, right);
            ProcessBuilder pb = new ProcessBuilder("diff", leftFile.toString(), rightFile.toString(), "--side-by-side");
            Process p = pb.start();
            p.waitFor();
            return new String(p.getInputStream().readAllBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
