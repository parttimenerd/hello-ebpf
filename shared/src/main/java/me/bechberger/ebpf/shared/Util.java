package me.bechberger.ebpf.shared;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
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

    public static String computeEditDistance(String a, String b) {
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) {
            for (int j = 0; j <= b.length(); j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] = Math.min(Math.min(dp[i - 1][j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1), dp[i - 1][j] + 1), dp[i][j - 1] + 1);
                }
            }
        }
        return Integer.toString(dp[a.length()][b.length()]);
    }

    public static String getClosestString(String target, Collection<String> options) {
        return options.stream().min(Comparator.comparing(a -> computeEditDistance(target, a))).orElse(target);
    }
}
