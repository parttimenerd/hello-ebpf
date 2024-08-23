package me.bechberger.ebpf.bpf;

import me.bechberger.ebpf.annotations.Unsigned;

import java.net.*;
import java.util.Collections;
import java.util.List;

/**
 * Utility functions for network related programs, like {@link XDPHook} and {@link TCHook}.
 */
public class NetworkUtil {
    public static final int XDP_FLAGS_UPDATE_IF_NOEXIST = 1;
    public static final int XDP_FLAGS_SKB_MODE = (1 << 1);
    public static final int XDP_FLAGS_DRV_MODE = (1 << 2);
    public static final int XDP_FLAGS_HW_MODE = (1 << 3);
    public static final int XDP_FLAGS_REPLACE = (1 << 4);
    public static final int XDP_FLAGS_MODES = (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE);
    public static final int XDP_FLAGS_MASK = (XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE);

    /** Get the index of the first network interface that is up and not a loopback interface, or -1 */
    public static int getNetworkInterfaceIndex() {
        return getNetworkInterfaceIndexes(false).stream().findFirst().orElse(-1);
    }

    /** Get the indixes of all network interfaces that are up and not a loopback interface (depending on the parameter) */
    public static List<Integer> getNetworkInterfaceIndexes(boolean includeLoopback) {
        try {
            return Collections.list(NetworkInterface.getNetworkInterfaces())
                    .stream().filter(i -> {
                        try {
                            return i.isUp() && (!i.isLoopback() || includeLoopback);
                        } catch (SocketException e) {
                            return false;
                        }
                    }).map(NetworkInterface::getIndex)
                    .toList();
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
    }

    /** Get the indixes of all network interfaces that are up and not loop back */
    public static List<Integer> getNetworkInterfaceIndexes() {
        return getNetworkInterfaceIndexes(false);
    }

    public static String getNetworkInterfaceName(int index) {
        try {
            return Collections.list(NetworkInterface.getNetworkInterfaces())
                    .stream().filter(iface -> iface.getIndex() == index)
                    .findFirst().orElseThrow().getDisplayName();
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

    /**
     * Open a connection to the given URL and read its content in a loop every second asynchronously.
     */
    public static void openURLInLoop(String url) {
        new Thread(() -> {
            try {
                while (true) {
                    System.out.println("Opening " + url);
                    URLConnection connection = URL.of(URI.create("https://" + url), null).openConnection();
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
            URLConnection connection = URL.of(URI.create("https://" + url), null).openConnection();
            return new String(connection.getInputStream().readAllBytes());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get the first IPv4 address of the given host name.
     */
    public static @Unsigned int getFirstIPAddress(String s) {
        try {
            return ipAddressToInt(InetAddress.getByName(s));
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] readFromURL(String url, int port) {
        try {
            URLConnection connection = URL.of(URI.create("https://" + url + ":" + port), null).openConnection();
            return connection.getInputStream().readAllBytes();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
