package me.bechberger.ebpf.gen;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.logging.Logger;

public class BTF {

    private static final Logger logger = Logger.getLogger(BTF.class.getName());

    private static Path getBTFJSONRaw() throws Exception {
        var tempDirectory = Files.createTempDirectory("vmlinux");
        tempDirectory.toFile().deleteOnExit();
        var tempFile = tempDirectory.resolve("vmlinux.json");
        var errorFile = tempDirectory.resolve("error.txt");
        var process = new ProcessBuilder("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format",
                "raw", "-j").redirectOutput(tempFile.toFile()).redirectError(errorFile.toFile()).start();
        if (process.waitFor() != 0) {
            logger.severe("Could not obtain vmlinux.h header file via 'bpftool btf "
                    + "dump file /sys/kernel/btf/vmlinux format c'\n" + Files.readString(errorFile));
        }
        return tempFile;
    }

    private static JSONObject getBTFJSON() throws Exception {
        var jsonFile = getBTFJSONRaw();
        var ret = JSON.parseObject(Files.readString(jsonFile));
        Files.delete(jsonFile);
        return ret;
    }

    public static JSONArray getBTFJSONTypes() throws Exception {
        var btf = getBTFJSON();
        if (!btf.keySet().equals(Set.of("types"))) {
            logger.warning("Unexpected JSON format, expected top-level object to only contain the key 'types', not " + btf.keySet());
        }
        return btf.getJSONArray("types");
    }
}
