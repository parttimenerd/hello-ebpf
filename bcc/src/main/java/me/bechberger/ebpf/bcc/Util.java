package me.bechberger.ebpf.bcc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

// based on bcc/utils.py
public class Util {
    /**
     *

     def _read_cpu_range(path):
     cpus = []
     with open(path, 'r') as f:
     cpus_range_str = f.read()
     for cpu_range in cpus_range_str.split(','):
     rangeop = cpu_range.find('-')
     if rangeop == -1:
     cpus.append(int(cpu_range))
     else:
     start = int(cpu_range[:rangeop])
     end = int(cpu_range[rangeop+1:])
     cpus.extend(range(start, end+1))
     return cpus

     def get_online_cpus():
     return _read_cpu_range('/sys/devices/system/cpu/online')

     def get_possible_cpus():
     return _read_cpu_range('/sys/devices/system/cpu/possible')
     */
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
