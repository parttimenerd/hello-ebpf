package me.bechberger.ebpf.samples;

import me.bechberger.ebpf.bpf.BPFProgram;
import me.bechberger.ebpf.bpf.NetworkUtil;
import me.bechberger.ebpf.samples.Firewall.FirewallAction;
import me.bechberger.ebpf.samples.Firewall.FirewallRule;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
            program.blockedConnections.setCallback((info) -> {
                System.out.println("Blocked packet from " +
                                   NetworkUtil.intToIpAddress(info.ip())
                                           .getHostAddress() + " port " + info.port());
            });
            FirewallController.firewall = program;
            new Thread(() -> SpringApplication.run(FirewallSpring.class, args)).start();
            while (true) {
                program.consumeAndThrow();
                Thread.sleep(500);
            }
        }
    }
}

@RestController
@RequestMapping("/")
class FirewallController {

    static Firewall firewall;

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
                            width: 100%;
                            padding: 8px;
                            margin-bottom: 15px;
                        }
                        button {
                            padding: 10px 20px;
                            background-color: #4CAF50;
                            color: white;
                            border: none;
                            cursor: pointer;
                        }
                        button:hover {
                            background-color: #45a049;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Firewall Control Interface</h2>
                
                        <div>
                            <h3>Send Custom JSON to /rawDrop</h3>
                            <p>Like <code>{"ip": 0, "ignoreLowBytes": 4, "port": 443}</code></p>
                            <textarea id="jsonInput"></textarea>
                            <button onclick="sendJson()">Send JSON</button>
                        </div>
                
                        <div>
                            <h3>Add a Rule to /add</h3>
                            <p>Like <code>google.com:HTTP drop</code></p>
                            <input type="text" id="ruleInput">
                            <button onclick="addRule()">Add Rule</button>
                        </div>
                
                        <div>
                            <h3>Clear All Rules via /reset</h3>
                            <button onclick="resetRules()">Reset Rules</button>
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
                    </script>
                </body>
                </html>
                """;
    }
}