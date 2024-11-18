// SPDX-License-Identifier: GPL-2.0

package me.bechberger.ebpf.samples;

import com.sun.net.httpserver.HttpServer;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BPF;
import me.bechberger.ebpf.annotations.bpf.BPFFunction;
import me.bechberger.ebpf.annotations.bpf.BPFMapDefinition;
import me.bechberger.ebpf.annotations.bpf.Property;
import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.Scheduler;
import me.bechberger.ebpf.bpf.map.BPFHashMap;
import me.bechberger.ebpf.type.Ptr;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Optional;

import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.task_struct;

/**
 * Minimal scheduler that allows stopping tasks via a REST API
 */
@BPF(license = "GPL")
@Property(name = "sched_name", value = "minimal_stopping_scheduler")
public abstract class MinimalStoppingScheduler extends BPFProgram implements Scheduler {

    private static final int SHARED_DSQ_ID = 0;

    @Type
    record TaskSetting(boolean stop) {
    }

    @BPFMapDefinition(maxEntries = 10000)
    BPFHashMap<Integer, TaskSetting> taskSettings;

    @Override
    public int init() {
        return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
    }

    @BPFFunction
    public boolean shouldStop(Ptr<task_struct> p) {
        var res = taskSettings.bpf_get(p.val().pid);
        return res != null && res.val().stop;
    }

    @Override
    public void enqueue(Ptr<task_struct> p, long enq_flags) {
        var sliceLength = ((@Unsigned int) 5_000_000) / scx_bpf_dsq_nr_queued(SHARED_DSQ_ID);
        if (shouldStop(p)) {
            sliceLength = 0; // this will prevent the task from being on the CPU
        }
        scx_bpf_dispatch(p, SHARED_DSQ_ID,  sliceLength, enq_flags);
    }

    @Override
    public void dispatch(int cpu, Ptr<task_struct> prev) {
        scx_bpf_consume(SHARED_DSQ_ID);
    }

    private static String SERVER_HELP = """
            GET localhost:PORT/task/{id} to get the status of a task
            GET localhost:PORT/task/{id}?stopping=true|false to stop or resume a task
            """;

    public void launchServer(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/help", exchange -> {
            String response = SERVER_HELP.replace("PORT", port + "");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        });
        server.createContext("/task", exchange -> {
            String method = exchange.getRequestMethod();
            if (!"GET".equalsIgnoreCase(method)) {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                return;
            }

            String path = exchange.getRequestURI().getPath();
            String[] segments = path.split("/");
            if (segments.length != 3) { // Expecting /task/{id}
                exchange.sendResponseHeaders(404, -1); // Not Found
                return;
            }

            // Extract the ID from the path
            int id;
            try {
                id = Integer.parseInt(segments[2]);
            } catch (NumberFormatException e) {
                exchange.sendResponseHeaders(400, -1); // Bad Request
                return;
            }

            // Parse query parameters
            Map<String, String> queryParams = HttpUtil.queryToMap(exchange.getRequestURI().getQuery());
            String stopping = queryParams.get("stopping");

            String response;
            if (stopping == null) {
                response = Optional.ofNullable(taskSettings.get(id))
                        .map(setting -> setting.stop ? "stopping" : "running")
                        .orElse("not found");
            } else {
                taskSettings.put(id, new TaskSetting(Boolean.parseBoolean(stopping)));
                response = "ok";
            }

            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        });
        server.setExecutor(null); // creates a default executor
        System.out.println("Starting server on port " + port);
        System.out.println(SERVER_HELP.replace("PORT", port + ""));
        server.start();
    }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        try (var program = BPFProgram.load(MinimalStoppingScheduler.class)) {
            program.attachScheduler();
            program.launchServer(port);
            Thread.sleep(100000000000000L);
        }
    }
}
