package me.bechberger.ebpf.shared;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class Util {
    public static List<Integer> getOnlineCPUs() {
        return readCPURange("/sys/devices/system/cpu/online");
    }

    public static List<Integer> getPossibleCPUs() {
        return readCPURange("/sys/devices/system/cpu/possible");
    }

    private static List<Integer> readCPURange(String path) {
        try {
            return Arrays.stream(Files.readAllLines(Path.of(path)).get(0).split(",")).flatMap(cpuRange -> {
                    int rangeOp = cpuRange.indexOf('-');
                    if (rangeOp == -1) {
                        return Stream.of(Integer.parseInt(cpuRange));
                    } else {
                        int start = Integer.parseInt(cpuRange.substring(0, rangeOp));
                        int end = Integer.parseInt(cpuRange.substring(rangeOp + 1));
                        return IntStream.range(start, end + 1).boxed();
                    }
            }).toList();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
