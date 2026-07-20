// SPDX-License-Identifier: GPL-2.0
package me.bechberger.ebpf.bpf.userspace;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.logging.Logger;

/**
 * Detects scheduling domains by grouping CPUs that share a last-level cache (LLC), read from
 * {@code /sys/devices/system/cpu/cpuN/cache/indexK/{level,shared_cpu_list}}. One domain per
 * distinct LLC-sharing group. Missing or unreadable cache info yields a single domain of all
 * online CPUs — {@link #detect} never throws.
 *
 * <p>Domains are numbered 0..nrDomains-1. A CPU's domain is {@link #domainOfCpu(int)}; a
 * domain's CPU set is the bitmask {@link #cpuMask(int)}.
 */
public final class CpuTopology {

    private static final Logger LOG = Logger.getLogger(CpuTopology.class.getName());
    private static final Path DEFAULT_ROOT = Path.of("/sys/devices/system/cpu");

    private final int nrCpus;
    private final int nrDomains;
    private final int[] cpuToDomain;   // index = cpu, value = domain id
    private final long[] domainMask;   // index = domain id, value = cpu bitmask

    private CpuTopology(int nrCpus, int nrDomains, int[] cpuToDomain, long[] domainMask) {
        this.nrCpus = nrCpus;
        this.nrDomains = nrDomains;
        this.cpuToDomain = cpuToDomain;
        this.domainMask = domainMask;
    }

    public int nrCpus() { return nrCpus; }
    public int nrDomains() { return nrDomains; }

    public int domainOfCpu(int cpu) {
        if (cpu < 0 || cpu >= cpuToDomain.length) return 0;
        return cpuToDomain[cpu];
    }

    public long cpuMask(int domain) {
        if (domain < 0 || domain >= domainMask.length) {
            throw new IllegalStateException("no such domain: " + domain);
        }
        return domainMask[domain];
    }

    public static CpuTopology detect() { return detect(DEFAULT_ROOT); }

    public static CpuTopology detect(Path sysfsRoot) {
        try {
            return detectOrThrow(sysfsRoot);
        } catch (RuntimeException e) {
            // Detection producing an inconsistent topology is a real bug — rethrow.
            if (e instanceof IllegalStateException) throw e;
            LOG.warning("CpuTopology: detection failed (" + e.getMessage()
                    + "); using a single all-CPU domain");
            return singleDomainFallback(countCpus(sysfsRoot));
        }
    }

    private static CpuTopology detectOrThrow(Path root) {
        List<Integer> cpus = listCpus(root);
        if (cpus.isEmpty()) {
            LOG.warning("CpuTopology: no cpuN dirs under " + root + "; assuming 1 CPU");
            return singleDomainFallback(1);
        }
        int maxCpu = cpus.stream().mapToInt(Integer::intValue).max().orElse(0);
        int nrCpus = maxCpu + 1;

        // For each CPU, find its highest-level (LLC) shared_cpu_list. Group by that string.
        Map<String, List<Integer>> llcGroups = new LinkedHashMap<>();
        boolean anyCache = false;
        for (int cpu : cpus) {
            String llc = highestSharedCpuList(root, cpu);
            if (llc == null) { anyCache = false; break; }
            anyCache = true;
            llcGroups.computeIfAbsent(llc, k -> new ArrayList<>()).add(cpu);
        }

        if (!anyCache || llcGroups.isEmpty()) {
            LOG.info("CpuTopology: no LLC cache info under " + root
                    + "; using a single domain of " + nrCpus + " CPUs");
            return singleDomainFallback(nrCpus);
        }

        int nrDomains = llcGroups.size();
        int[] cpuToDomain = new int[nrCpus];
        long[] domainMask = new long[nrDomains];
        int dom = 0;
        for (var e : llcGroups.entrySet()) {
            for (int cpu : e.getValue()) {
                cpuToDomain[cpu] = dom;
                domainMask[dom] |= (1L << cpu);
            }
            if (domainMask[dom] == 0L) {
                throw new IllegalStateException("empty cpuMask for domain " + dom);
            }
            dom++;
        }
        if (nrDomains > nrCpus) {
            throw new IllegalStateException("more domains (" + nrDomains
                    + ") than CPUs (" + nrCpus + ")");
        }
        return new CpuTopology(nrCpus, nrDomains, cpuToDomain, domainMask);
    }

    /** Return the shared_cpu_list of the highest-level cache for {@code cpu}, or null. */
    private static String highestSharedCpuList(Path root, int cpu) {
        Path cacheDir = root.resolve("cpu" + cpu).resolve("cache");
        if (!Files.isDirectory(cacheDir)) return null;
        String best = null;
        int bestLevel = -1;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(cacheDir, "index*")) {
            for (Path idx : ds) {
                Path levelP = idx.resolve("level");
                Path sharedP = idx.resolve("shared_cpu_list");
                if (!Files.isReadable(levelP) || !Files.isReadable(sharedP)) continue;
                int level = Integer.parseInt(Files.readString(levelP).trim());
                if (level > bestLevel) {
                    bestLevel = level;
                    best = Files.readString(sharedP).trim();
                }
            }
        } catch (IOException | NumberFormatException e) {
            return null;
        }
        return best;
    }

    private static List<Integer> listCpus(Path root) {
        List<Integer> cpus = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(root, "cpu[0-9]*")) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                String num = name.substring("cpu".length());
                if (num.chars().allMatch(Character::isDigit)) {
                    cpus.add(Integer.parseInt(num));
                }
            }
        } catch (IOException e) {
            // fall through -> empty
        }
        cpus.sort(Integer::compareTo);
        return cpus;
    }

    private static int countCpus(Path root) {
        int n = listCpus(root).size();
        return n > 0 ? n : Runtime.getRuntime().availableProcessors();
    }

    private static CpuTopology singleDomainFallback(int nrCpus) {
        int[] cpuToDomain = new int[nrCpus];   // all zeros
        long mask = nrCpus >= 64 ? -1L : ((1L << nrCpus) - 1);
        return new CpuTopology(nrCpus, 1, cpuToDomain, new long[]{mask});
    }
}
