package me.bechberger.ebpf.samples;

import java.util.HashMap;
import java.util.Map;

public class HttpUtil {
    public static Map<String, String> queryToMap(String query) {
        Map<String, String> map = new HashMap<>();
        if (query == null) {
            return map;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] entry = pair.split("=", 2);
            if (entry.length > 1) {
                map.put(entry[0], entry[1]);
            } else {
                map.put(entry[0], "");
            }
        }
        return map;
    }
}
