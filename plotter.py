#!/usr/bin/env python3
import matplotlib.pyplot as plt

LOG_FILE = "h1.log"

# --- Parse the log ---
domain_final_data = {}  # {domain: {'servers': count, 'latency': float}}

with open(LOG_FILE, "r", encoding="utf-8") as f:
    temp_servers = {}  # Temporary storage to count unique servers per domain
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            entry = eval(line)
            domain = entry.get("domain_name")
            server_ip = entry.get("dns_server_ip")
            
            # Track unique servers per domain
            if domain not in temp_servers:
                temp_servers[domain] = set()
            if server_ip:
                temp_servers[domain].add(server_ip)
            
            # Only consider entries that have actual latency (resolved)
            total_time = entry.get("total_time_to_resolution")
            if total_time != "N/A":
                try:
                    latency = float(total_time.replace("s", ""))  # remove 's'
                except ValueError:
                    print("Invalid total_time:", total_time)
                    continue
                servers_visited = len(temp_servers[domain])
                if domain not in domain_final_data:
                    domain_final_data[domain] = {'servers': servers_visited, 'latency': latency}
        except Exception:
            continue

# Take first 10 unique domains
first_domains = list(domain_final_data.keys())[:10]
if not first_domains:
    print("No valid resolved entries found in log.")
    exit(0)

servers_visited = [domain_final_data[d]['servers'] for d in first_domains]
latencies = [domain_final_data[d]['latency'] for d in first_domains]

# --- Plot total servers visited ---
plt.figure(figsize=(10,5))
plt.bar(range(len(first_domains)), servers_visited, color='skyblue')
plt.xticks(range(len(first_domains)), first_domains, rotation=45, ha='right')
plt.ylabel("Total Servers Visited")
plt.title("Total DNS Servers Visited per URL (First 10 URLs)")
plt.tight_layout()
plt.show()

# --- Plot latency per query ---
plt.figure(figsize=(10,5))
plt.bar(range(len(first_domains)), latencies, color='orange')
plt.xticks(range(len(first_domains)), first_domains, rotation=45, ha='right')
plt.ylabel("Latency (s)")
plt.title("Latency per Query per URL (First 10 URLs)")
plt.tight_layout()
plt.show()
