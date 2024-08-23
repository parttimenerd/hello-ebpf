package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.NetworkUtil;
import me.bechberger.ebpf.samples.Firewall.FirewallAction;
import me.bechberger.ebpf.samples.Firewall.FirewallRule;
import me.bechberger.ebpf.samples.Firewall.LogEntry;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

/**
 * A spring boot based front-end for the Firewall
 */
@SpringBootApplication(scanBasePackages = "me.bechberger.ebpf.samples")
public class FirewallSpring {

    public static void main(String[] args) throws InterruptedException {
        System.setProperty("server.port", "8080");
        System.setProperty("server.address", "0.0.0.0");
        try (Firewall program = BPFProgram.load(Firewall.class)) {
            program.xdpAttach();
            program.blockedConnections.setCallback(FirewallSpring::log);
            FirewallController.firewall = program;
            new Thread(() -> SpringApplication.run(FirewallSpring.class, args)).start();
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(100);
            }
        }
    }

    static void log(LogEntry logEntry) {
        System.out.println(logEntry.timeInMs() + ": Blocked packet from " +
                NetworkUtil.intToIpAddress(logEntry.connection().ip()).getHostAddress() +
                           " port " + logEntry.connection().ip());
        FirewallController.log.add(logEntry);
        if (FirewallController.log.size() > 1000) {
            FirewallController.log.removeFirst();
        }
    }
}

@RestController
@RequestMapping("/")
class FirewallController {

    static Firewall firewall;
    static List<LogEntry> log = new ArrayList<>();

    @PostMapping("/rawDrop")
    ResponseEntity<Void> rawDrop(@RequestBody FirewallRule rule) {
        addRule(rule, FirewallAction.DROP);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/add")
    ResponseEntity<Void> add(@RequestBody String rule) {
        var parsed = Firewall.parseRule(rule);
        addRule(parsed.rule(), parsed.action());
        return ResponseEntity.ok().build();
    }

    private void addRule(FirewallRule rule, FirewallAction action) {
        System.out.println("Adding rule: " + rule + " action: " + action);
        validateRule(rule);
        firewall.firewallRules.put(rule, action);
        firewall.resolvedRules.clear();
    }

    private void validateRule(FirewallRule rule) {
        if (rule.ignoreLowBytes() < 0 || rule.ignoreLowBytes() > 4) {
            throw new IllegalArgumentException("Invalid ignoreLowBytes: " +
                                               rule.ignoreLowBytes() + " must be between 0 and 4");
        }
    }

    @PostMapping("/reset")
    ResponseEntity<Void> reset() {
        firewall.firewallRules.clear();
        firewall.resolvedRules.clear();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/logs")
    ResponseEntity<List<LogEntry>> getLogs() {
        return ResponseEntity.ok(log);
    }

    @PostMapping("/triggerRequest")
    ResponseEntity<Void> triggerRequest(@RequestBody String url) {
        new Thread(() -> {
            try {
                System.out.println("Opening " + url);
                Process process = new ProcessBuilder("wget", "-q", url, "--timeout=5").start();
                process.waitFor();
            } catch (Exception e) {
            }
        }).start();
        return ResponseEntity.ok().build();
    }


    @GetMapping("/")
    @ResponseBody
    public String index() {
        return """
                <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Firewall Control</title>
                        <style>
                            body {
                                font-family: Arial, sans-serif;
                                margin: 40px;
                            }
                            .container {
                                max-width: 600px;
                                margin: 0 auto;
                            }
                            h2 {
                                color: #333;
                            }
                            label {
                                display: block;
                                margin: 15px 0 5px;
                            }
                            input, textarea {
                                padding: 8px;
                                margin-bottom: 15px;
                            }
                            button {
                                margin-bottom: 15px;
                                padding: 10px 20px;
                                background-color: #4CAF50;
                                color: white;
                                border: none;
                                cursor: pointer;
                                width: 150px; /* Fixed width for all buttons */
                            }
                            button:hover {
                                background-color: #45a049;
                            }
                            #logArea {
                                border: 1px solid #ccc;
                                padding: 10px;
                                height: 200px;
                                overflow-y: scroll;
                                background-color: #f9f9f9;
                            }
                            .logEntry {
                                margin-bottom: 5px;
                                padding: 5px;
                                border-bottom: 1px solid #ddd;
                            }
                            .input-group {
                                display: flex;
                                align-items: center;
                                gap: 10px;
                            }
                            .input-group input {
                                flex: 1;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h2>Firewall Control Interface</h2>
                
                            <div>
                                <h3>Send Custom JSON to /rawDrop</h3>
                                <p>Like <code>{"ip": 0, "ignoreLowBytes": 4, "port": 443}</code></p>
                                <div class="input-group">
                                    <input type="text" id="jsonInput" value='{"ip": 0, "ignoreLowBytes": 4, "port": 443}'>
                                    <button onclick="sendJson()">Send JSON</button>
                                </div>
                            </div>
                
                            <div>
                                <h3>Add a Rule to /add</h3>
                                <p>Like <code>google.com:HTTP drop</code></p>
                                <div class="input-group">
                                    <input type="text" id="ruleInput">
                                    <button onclick="addRule()">Add Rule</button>
                                </div>
                            </div>
                
                            <div>
                                <h3>Clear All Rules via /reset</h3>
                                <button onclick="resetRules()">Reset Rules</button>
                            </div>
                
                            <div>
                                <h3>Trigger Request</h3>
                                <form id="triggerGetForm" class="input-group">
                                    <input type="text" id="urlInput" value="https://google.com">
                                    <button type="button" onclick="triggerRequest()">Request</button>
                                </form>
                            </div>
                
                            <div>
                                <h3>Blocked Logs</h3>
                                <div id="logArea"></div>
                            </div>
                        </div>
                
                        <script>
                            function sendJson() {
                                const json = document.getElementById('jsonInput').value;
                                fetch('/rawDrop', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: json,
                                }).then(response => {
                                    if (!response.ok) {
                                        throw new Error('Network response was not ok');
                                    }
                                    document.getElementById('jsonInput').value = '';
                                }).catch(error => {
                                    alert('Error: ' + error.message);
                                });
                            }
                
                            function addRule() {
                                const rule = document.getElementById('ruleInput').value;
                
                                fetch('/add', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: rule,
                                }).then(response => {
                                    if (!response.ok) {
                                        throw new Error('Network response was not ok');
                                    }
                                    document.getElementById('ruleInput').value = '';
                                }).catch(error => {
                                    alert('Error: ' + error.message);
                                });
                            }
                
                            function resetRules() {
                                fetch('/reset', {
                                    method: 'POST',
                                }).catch(error => {
                                    alert('Error: ' + error.message);
                                });
                            }
                
                            function triggerRequest() {
                                const url = document.getElementById('urlInput').value;
                
                                fetch('/triggerRequest', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: url,
                                }).then(response => {
                                    if (!response.ok) {
                                        throw new Error('Network response was not ok');
                                    }
                                    document.getElementById('urlInput').value = "";
                                }).catch(error => {
                                    alert('Error: ' + error.message);
                                });
                            }
                
                            function fetchLogs() {
                                fetch('/logs')
                                    .then(response => response.json())
                                    .then(data => {
                                        const logArea = document.getElementById('logArea');
                                        const existingLogs = Array.from(logArea.children).map(child => child.dataset.log);
                                        data.reverse().forEach(log => {
                                            if (log.connection.port !== 8080 && !existingLogs.includes(log.timeInMs.toString())) {
                                                const logEntry = document.createElement('div');
                                                logEntry.className = 'logEntry';
                                                logEntry.dataset.log = log.timeInMs.toString();
                
                                                const date = new Date(log.timeInMs);
                                                const formattedTime = `${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}.${String(date.getMilliseconds()).padStart(3, '0')}`;
                                                const timeSpan = document.createElement('span');
                                                timeSpan.style.color = 'darkgrey';
                                                timeSpan.style.display = 'inline-block';
                                                timeSpan.style.width = '80px';
                                                timeSpan.textContent = formattedTime;
                
                                                const ip = log.connection.ip;
                                                const ipParts = [
                                                    (ip >> 24) & 0xFF,
                                                    (ip >> 16) & 0xFF,
                                                    (ip >> 8) & 0xFF,
                                                    ip & 0xFF
                                                ].map(part => part.toString());
                                                const formattedIp = `${ipParts[0]}:${ipParts[2]}:${ipParts[1]}:${ipParts[3]}`;
                
                                                const ipSpan = document.createElement('span');
                                                ipSpan.style.color = 'black';
                                                ipSpan.textContent = formattedIp;
                
                                                const portSpan = document.createElement('span');
                                                portSpan.style.color = 'black';
                                                portSpan.textContent = log.connection.port;
                
                                                const textSpan = document.createElement('span');
                                                textSpan.style.color = 'grey';
                                                textSpan.textContent = `: blocked packet from `;
                
                                                const textSpan2 = document.createElement('span');
                                                textSpan2.style.color = 'grey';
                                                textSpan2.textContent = ` to port `;
                
                                                logEntry.appendChild(timeSpan);
                                                logEntry.appendChild(textSpan);
                                                logEntry.appendChild(ipSpan);
                                                logEntry.appendChild(textSpan2);
                                                logEntry.appendChild(portSpan);
                                                logArea.prepend(logEntry);
                                            }
                                        });
                                    });
                            }
                
                            setInterval(fetchLogs, 100);
                        </script>
                    </body>
                    </html>
            """;
    }
}