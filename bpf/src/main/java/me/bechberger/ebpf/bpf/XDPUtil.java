package me.bechberger.ebpf.bpf;

import java.net.*;
import java.util.ArrayList;
import java.util.Collections;

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

    public static int ipAddressToInt(InetAddress addr) {
        byte[] bytes = addr.getAddress();
        return bytes[3] << 24 | (bytes[2] & 0xFF) << 16 | (bytes[1] & 0xFF) << 8 | (bytes[0] & 0xFF);
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
}
