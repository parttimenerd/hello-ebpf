package me.bechberger.ebpf.shared.util;

import org.jetbrains.annotations.Nullable;

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
     * Read a line from the file, or return null if the file is closed, might block
     */
    public @Nullable String readLine() {
        try {
            return reader.readLine();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Read a line from the file if there is content available, or return null
     * @return the line or null if no line is available
     */
    public @Nullable String readLineIfPossible() {
        if (ready()) {
            return readLine();
        }
        return null;
    }

    /**
     * Check if the reader is ready to read a line and has content available
     * @return true if a line can be read without blocking
     */
    public boolean ready() {
        try {
            return reader.ready();
        } catch (IOException e) {
            return false;
        }
    }
}
