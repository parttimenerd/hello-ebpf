package me.bechberger.ebpf.bcc;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Read lines from a file and can be interrupted at any time.
 * <p>
 * Normally BufferedReader.readLine() blocks until a line is available, but we can
 * just close the wrapped InputStream to interrupt it.
 */
public class LineReader {

    private final InputStream input;
    private final BufferedReader reader;

    /**
     * Create a file reader, reading from the passed file
     *
     * @param path the file to read from
     */
    public LineReader(Path path) throws IOException {
        this.input = Files.newInputStream(path);
        this.reader = new BufferedReader(new InputStreamReader(input));
    }

    /**
     * Close the file
     */
    public void close() {
        try {
            input.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Read a line from the file, or return null if the file is closed
     */
    public String readLine() {
        try {
            return reader.readLine();
        } catch (IOException e) {
            return null;
        }
    }
}
