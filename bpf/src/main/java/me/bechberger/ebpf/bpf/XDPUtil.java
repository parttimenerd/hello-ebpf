package me.bechberger.ebpf.bpf;

import java.net.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class XDPUtil {
    public static final int XDP_FLAGS_UPDATE_IF_NOEXIST = 1;
    public static final int XDP_FLAGS_SKB_MODE = (1 << 1);
    public static final int XDP_FLAGS_DRV_MODE = (1 << 2);
    public static final int XDP_FLAGS_HW_MODE = (1 << 3);
    public static final int XDP_FLAGS_REPLACE = (1 << 4);
    public static final int XDP_FLAGS_MODES = (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE);
    public static final int XDP_FLAGS_MASK = (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE);

    /** Get the index of the first network interface that is up and not a loopback interface, or -1 */
    public static int getNetworkInterfaceIndex() {
        try {
            ArrayList<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface iface : interfaces) {
                if (iface.isUp() && !iface.isLoopback()) {
                    return iface.getIndex();
                }
            }
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
        return -1;
    }

    public static List<Integer> getNetworkInterfaceIndices() {
        try {
            return Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                    .map(NetworkInterface::getIndex)
                    .collect(Collectors.toList());
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    public static int ipAddressToInt(InetAddress addr) {
        byte[] bytes = addr.getAddress();
        return bytes[3] << 24 | (bytes[2] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF);
    }

    public static int ipAddressToInt(String addr) {
        if (addr.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return ipAddressToInt(InetAddress.ofLiteral(addr));
        }
        try {
            return ipAddressToInt(InetAddress.getByName(addr));
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static InetAddress intToIpAddress(int addr) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (addr & 0xFF);
        bytes[1] = (byte) ((addr >> 8) & 0xFF);
        bytes[2] = (byte) ((addr >> 16) & 0xFF);
        bytes[3] = (byte) ((addr >> 24) & 0xFF);
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private static URL urlToUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        try {
            return URL.of(URI.create(url), null);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Open a connection to the given URL and read its content in a loop every second asynchronously.
     */
    public static void openURLInLoop(String url) {
        new Thread(() -> {
            try {
                while (true) {
                    System.out.println("Opening " + url);
                    URLConnection connection = urlToUrl(url).openConnection();
                    System.out.println("Read " + connection.getInputStream().readAllBytes().length + " bytes");
                    Thread.sleep(1000);
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }).start();
    }

    public static String openURL(String url) {
        try {
            URLConnection connection = urlToUrl(url).openConnection();
            return new String(connection.getInputStream().readAllBytes());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
