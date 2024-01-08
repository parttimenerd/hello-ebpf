package me.bechberger.ebpf.bcc;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/** Utility methods for histograms, used by {@link BPFTable} */
class HistogramUtils {

    public static final int STARS_MAX = 40;
    public static final int LOG2_INDEX_MAX = 65;
    public static final int LINEAR_INDEX_MAX = 1025;

    public record HistorgramEntry(int intervalStart, int intervalEnd, int count) {
    }

    /**
     * Translation of BCC's JSON histogram
     * @param ts time stamp
     * @param valType value type
     * @param data histogram data
     */
    public record Histogram(String ts, String valType, List<HistorgramEntry> data) {
    }
    /*
    def _get_json_hist(vals, val_type, section_bucket=None):

     */
    /** Translation of BCC's <code>_get_json_hist</code>*/
    public static Histogram _getJsonHist(List<Integer> values, String valType) {
        var histList = new java.util.ArrayList<HistorgramEntry>();
        int maxNonZeroIdx = 0;
        for (int i = 0; i < values.size(); i++) {
            if (values.get(i) != 0) {
                maxNonZeroIdx = i;
            }
        }
        int index = 1;
        int prev = 0;
        for (int i = 0; i < values.size(); i++) {
            if (i != 0 && i <= maxNonZeroIdx) {
                index = index * 2;
                var listObj = new HistorgramEntry(prev, index - 1, values.get(i));
                histList.add(listObj);
                prev = index;
            }
        }
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = LocalDateTime.now().format(formatter);
        return new Histogram(formattedDateTime, valType, histList);
    }


    /** Translation of BCC's <code>_stars</code>*/
    public static String _stars(int val, int valMax, int width) {
        int i = 0;
        StringBuilder text = new StringBuilder();
        while (true) {
            if (i > (width * val / valMax) - 1 || i > width - 1) {
                break;
            }
            text.append("*");
            i += 1;
        }
        if (val > valMax) {
            text = new StringBuilder(text.substring(0, text.length() - 1) + "+");
        }
        return text.toString();
    }

    /*
    def _print_linear_hist(vals, val_type, strip_leading_zero):
    global stars_max
    log2_dist_max = 64
    idx_max = -1
    val_max = 0

    for i, v in enumerate(vals):
        if v > 0: idx_max = i
        if v > val_max: val_max = v

    header = "     %-13s : count     distribution"
    body = "        %-10d : %-8d |%-*s|"
    stars = stars_max

    if idx_max >= 0:
        print(header % val_type)
    for i in range(0, idx_max + 1):
        val = vals[i]

        if strip_leading_zero:
            if val:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))
                strip_leading_zero = False
        else:
                print(body % (i, val, stars,
                              _stars(val, val_max, stars)))
     */
    /** Translation of BCC's <code>_print_linear_hist</code>*/
    public static void printLinearHist(List<Integer> values, String valType, boolean stripLeadingZero) {
        int valMax = 0;
        int idxMax = -1;
        for (int i = 0; i < values.size(); i++) {
            if (values.get(i) > 0) {
                idxMax = i;
            }
            if (values.get(i) > valMax) {
                valMax = values.get(i);
            }
        }
        String header = "     %-13s : count     distribution";
        String body = "        %-10d : %-8d |%-*s|";
        int stars = STARS_MAX;
        if (idxMax >= 0) {
            System.out.printf(header + "%n", valType);
        }
        for (int i = 0; i < idxMax + 1; i++) {
            int val = values.get(i);
            if (stripLeadingZero) {
                if (val != 0) {
                    System.out.printf(body + "%n", i, val, stars, _stars(val, valMax, stars));
                    stripLeadingZero = false;
                }
            } else {
                System.out.printf(body + "%n", i, val, stars, _stars(val, valMax, stars));
            }
        }
    }
}
