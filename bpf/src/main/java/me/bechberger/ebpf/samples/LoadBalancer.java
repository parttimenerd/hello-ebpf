package me.bechberger.ebpf.samples;

import com.sun.net.httpserver.HttpServer;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Type;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.GlobalVariable;
import me.bechberger.ebpf.bpf.GlobalVariable.Globals;
import me.bechberger.ebpf.bpf.XDPUtil;
import me.bechberger.ebpf.bpf.map.BPFArray;
import me.bechberger.ebpf.bpf.map.BPFLRUHashMap;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Basic XDP-based load balancer
 */
@BPF(license = "GPL")
@Command(name = "Load balancer", mixinStandardHelpOptions = true,
        description = "Load balancer using XDP to distribute incoming packages to multiple servers")
public abstract class LoadBalancer extends BPFProgram implements Runnable {

    final GlobalVariable<@Unsigned Integer> portGlobal = new GlobalVariable<>(0);

    @Type(name = "address")
    record Address(@Unsigned int ip, @Unsigned int port) {}

    /**
     * Maps a client source address to a server address for persistence
     */
    @BPFMapDefinition(maxEntries = 10000)
    BPFLRUHashMap<Address, Address> clientToServerAddress;

    private static final int MAX_AV_SERVERS = 100;

    record AvailableServers(int count, @Size(MAX_AV_SERVERS) Address[] servers) {
        static AvailableServers create(List<Address> servers) {
            return new AvailableServers(servers.size(), servers.toArray(new Address[0]));
        }
    }

    final GlobalVariable<AvailableServers> availableServers = new GlobalVariable<>(AvailableServers.create(Collections.emptyList()));

    public static final String EBPF_PROGRAM = """
            #include <vmlinux.h>
            #include <bpf/bpf_helpers.h>
            #include <bpf/bpf_endian.h>

            // copied from the linux kernel
            #define ETH_P_8021Q 0x8100
            #define ETH_P_8021AD 0x88A8
            #define ETH_P_IP 0x0800
            #define ETH_P_IPV6 0x86DD
            #define ETH_P_ARP 0x0806            

            /** servers[ip * port % #servers] */
            bool get_new_ip_address(struct address client, struct address* ret) {
                unsigned int size = availableServers.count;
                if (size == 0) return false;
                
                int index = (client.ip * client.port) - ((client.ip * client.port) / size) * size ;
                
                *ret = availableServers.servers[index];
                return true;
            }
            
            bool is_valid_server_address(struct address addrToCheck) {
                // check that the list of available servers contains this address
                int size = availableServers.count;
                for (int i = 0; i < size && i < MAX_AV_SERVERS; i++) {
                    struct address addr = availableServers.servers[i];
                    if (addr.ip == addrToCheck.ip && addr.port == addrToCheck.port) return true;
                }
                return false;
            }
            
            // Idea: check if ip address is already in clientToServerAddress and valid, if not compute new
            // and store
            // returns {0, 0} in ret on error
            void get_ip_address(struct address client, struct address *ret) {
                struct address *server = bpf_map_lookup_elem(&clientToServerAddress, &client);
                if (server == NULL || !is_valid_server_address(*server)) {
                    // server is not valid, so create new
                    struct address newServer;
                    if (!get_new_ip_address(client, &newServer)) {
                        // no server available
                        *ret = (struct address){0, 0};
                        return;
                    }
                    bpf_map_update_elem(&clientToServerAddress, &client, &newServer, BPF_ANY);
                    *ret = newServer;
                    return;
                }
                *ret = *server;
            }
            
            // TODO: "just" parse the IP, and TCP headers, modify IP and port
            
            SEC("xdp")
            int load_balancer(struct xdp_md *ctx) {
                // start with getting the IP packet like in the XDPPacketFilter
                void *data_end = (void *)(long)ctx->data_end;
                void *data = (void *)(long)ctx->data;
                void *head = data;
                struct ethhdr *eth;
                struct iphdr *iph;
                struct tcphdr *tcph;
                uint16_t h_proto;
                uint8_t *tcp_data;
                int nbzeros = 0;
                int i = 0;
                bool found = false;
               
                eth = head;
                if ((void *)eth + sizeof(struct ethhdr) >= data_end)
                    return XDP_PASS;
                head += sizeof(struct ethhdr);
            
                h_proto = eth->h_proto;
        
                if (h_proto != bpf_htons(ETH_P_IP))
                    return XDP_PASS;
    
                iph = head;
                if ((void *)iph + sizeof(struct iphdr) >= data_end)
                    return XDP_PASS;
        
                h_proto = iph->protocol;
        
                head += iph->ihl * 4;
    
                if (h_proto != IPPROTO_TCP)
                    return XDP_PASS;
                tcph = head;
                if ((void *)tcph + sizeof(*tcph) > data_end)
                    return XDP_PASS;
                head += sizeof(*tcph);
            
                if (head + tcph->doff * 4 > data_end)
                    return XDP_PASS;
                head += tcph->doff * 4;
            
                int port = bpf_ntohs(tcph->dest);
                    
                if (tcph->dest != port)
                    return XDP_PASS;
                
                bpf_printk("Received packet with destination port %d\\n", tcph->dest);
    
                return XDP_PASS;
            }
            

            """;

    // TODO: specify available servers in file and read it every second
    @Parameters(paramLabel = "PORT", description = "The port to listen on")
    int port;

    @Parameters(paramLabel = "SERVER_FILE", description = "File that contains the servers to distribute the packages to, one per line, format 'IP:PORT'", arity = "1")
    Path serversFile;

    @Option(names = "--testClients", description = "Number of test clients to start, " +
            "that ask for the test server every 10 seconds, assumes all available servers start with 'localhost'",
            defaultValue = "0")
    int testClientNumber;

    void startTestServer(int port) throws IOException {
        // start a test HTTP server at localhost:port that prints "Port $port" in a daemon thread
        HttpServer.create(new InetSocketAddress(port), 0, "/", exchange -> {
            var response = "Port " + port;
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        }).start();
    }

    void startTestServers(List<Address> targetServers) throws IOException {
        // start test servers at availableServers (assert that the IP address is localhost and the port is different)
        for (Address server : targetServers) {
            if (server.ip() != XDPUtil.ipAddressToInt("localhost")) {
                throw new IllegalArgumentException("Only localhost is supported as server address");
            }
            if (server.port() == port) {
                throw new IllegalArgumentException("Server port must be different from the load balancer port");
            }
            startTestServer(server.port());
        }
    }

    void testClientMain() {
        while (true) {
            // load test from localhost:port and print
            System.out.println("thread");
            System.out.println(Thread.currentThread().getName() + " received: " + XDPUtil.openURL("http://localhost:" + port));
            System.out.println("thread finished");
            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
                break;
            }
        }
    }

    void startTestClients() {
        for (int i = 0; i < testClientNumber; i++) {
            var t = new Thread(this::testClientMain);
            t.setDaemon(true);
            t.setName("Test client " + i);
            t.start();
        }
    }

    void startTestCodeIfNeeded() {
        if (testClientNumber > 0) {
            try {
                startTestServers(readAddressList(serversFile));
                startTestClients();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    List<Address> readAddressList(Path file) throws IOException {
        // read file line by line and parse IP:PORT
        return Files.readAllLines(file).stream()
                .map(line -> {
                    var parts = line.split(":");
                    return new Address(XDPUtil.ipAddressToInt(parts[0]), Integer.parseInt(parts[1]));
                })
                .toList();
    }

    void updateAvailableServers() throws IOException {
        availableServers.set(AvailableServers.create(readAddressList(serversFile)));
    }

    void dataPlane() {
        new Thread(() -> {
            while (true) {
                try {
                    updateAvailableServers();
                    Thread.sleep(1000);
                } catch (InterruptedException | IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }

    @Override
    public void run() {
        // store target server addresses into map
        try {
            updateAvailableServers();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        portGlobal.set(port);
        try {
            HttpServer.create(new InetSocketAddress(port), 0, "/", exchange -> {
                var response = "Test response on port " + port;
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.close();
            }).start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        startTestCodeIfNeeded();
        for (var idx : XDPUtil.getNetworkInterfaceIndices()) {
            xdpAttach(getProgramByName("load_balancer"), idx);
        }
        dataPlane();
        tracePrintLoop();
    }


    public static void main(String[] args) {
        try (LoadBalancer program = BPFProgram.load(LoadBalancer.class)) {
            var cmd = new CommandLine(program);
            cmd.parseArgs(args);
            if (cmd.isUsageHelpRequested()) {
                cmd.usage(System.out);
                return;
            }
            program.run();
        }
    }
}
