# How to Run

## Prerequisites
- Use the PCAP files in the **PCAP folder** (filtered version containing only valid DNS query packets)
- Ensure Mininet is installed and properly configured
- Required Python libraries: Scapy, TShark, and other dependencies as specified in the scripts

---

## Part A: Network Topology Setup and Connectivity Testing

1. **Run the topology script directly in Mininet:**
```bash
   sudo python3 PartA.py
```

2. **Expected Output:**
   - Network topology will be created with 4 hosts (h1-h4), 4 switches (s1-s4), and a DNS resolver
   - `pingAll` test will verify connectivity across all 20 host pairs

---

## Part B: DNS Resolution with External Resolver

1. **Run the DNS performance test in Mininet:**
```bash
   sudo python3 PartB.py
```

2. **Expected Behavior:**
   - Hosts h1-h4 will query the external Google DNS server (8.8.8.8)
   - DNS performance metrics will be collected and displayed
   - Results include throughput, average latency, and query success/failure rates

---

## Part D: DNS Resolution with Custom Resolver

### Step 1: Setup Network and Launch Mininet CLI
```bash
sudo python3 PartD.py
```
This will set up the network topology and open the Mininet CLI.

### Step 2: Launch Custom DNS Resolver on h5
1. **Open h5 terminal:**
```bash
   mininet> xterm h5
```

2. **Run the custom DNS resolver:**
```bash
   sudo python3 custom_resolver.py 53535
```
   - The resolver will listen on UDP port 53535
   - All resolution steps will be logged to `resolver.log`

### Step 3: Run Client Queries from Hosts h1-h4
1. **Open terminals for each host:**
```bash
   mininet> xterm h1
   mininet> xterm h2
   mininet> xterm h3
   mininet> xterm h4
```

2. **Run the client script on each host:**
   
   **For h1:**
```bash
   sudo python3 clientRun.py h1_dns.pcap 10.0.0.5 5353
```
   
   **For h2:**
```bash
   sudo python3 clientRun.py h2_dns.pcap 10.0.0.5 5353
```
   
   **For h3:**
```bash
   sudo python3 clientRun.py h3_dns.pcap 10.0.0.5 5353
```
   
   **For h4:**
```bash
   sudo python3 clientRun.py h4_dns.pcap 10.0.0.5 5353
```

3. **Monitor Progress:**
   - Each client will display a progress bar showing query completion
   - Metrics will be computed and displayed at the end

---

## Results and Logs

All experimental results are available in the **results/** folder:

### Log Files

- **`hi_log`** (where i = 1, 2, 3, 4):
  - Contains detailed DNS query logs from the custom resolver
  - Includes per-query metrics: timestamps, DNS servers contacted, cache status, round-trip times, and resolution outcomes

- **`hi_partD.log`** (where i = 1, 2, 3, 4):
  - Contains the console output from each host during query execution


### Plots

Three visualization plots are provided:

1. **DNS Latency per Query** - Shows response time for each DNS query
2. **Total DNS Servers Visited** - Displays the number of DNS servers contacted per query

### Metric Screenshots

Performance metric screenshots for each host (h1-h4) showing:
- Total queries processed
- Successful vs. failed queries
- Average latency (seconds)
- Throughput (Bps)

---

## Notes

- Ensure sufficient permissions (sudo) when running scripts
- The custom resolver performs iterative resolution starting from root servers
- Network delays are simulated according to the topology configuration
- Query failures may occur due to timeouts, unreachable servers, or incomplete delegation chains
