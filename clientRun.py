#!/usr/bin/env python3
import sys
import subprocess
import time
import statistics

def extract_domains_from_pcap(pcap_file):
    """Extracts unique DNS query domains from a PCAP using TShark."""
    try:
        tshark_cmd = [
            "tshark",
            "-r", pcap_file,
            "-Y", "dns.flags.response == 0 && dns.qry.name",
            "-T", "fields",
            "-e", "dns.qry.name"
        ]
        proc = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output = proc.stdout.decode("utf-8").splitlines()
    except FileNotFoundError:
        print("ERROR: TShark not installed.", file=sys.stderr)
        return []
    except subprocess.CalledProcessError as e:
        print("ERROR running TShark:", e.stderr.decode("utf-8"), file=sys.stderr)
        return []

    seen = set()
    domains = []
    for d in output:
        d = d.strip().strip(".")
        if d and d not in seen:
            domains.append(d)
            seen.add(d)
    return domains

def send_query_with_dig(domain, resolver_ip, port):
    """Send a single DNS query using dig and measure latency."""
    dig_cmd = ["dig", "@%s" % resolver_ip, "-p", str(port), domain, "+time=5", "+tries=1", "+short"]
    start = time.time()
    try:
        proc = subprocess.run(dig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
        print(proc)
        latency = time.time() - start
        output = proc.stdout.decode("utf-8").strip()
        success = bool(output)
    except subprocess.TimeoutExpired:
        print("Query for %s timed out." % domain)
        latency = 5.0
        success = False
    return latency, success

def compute_metrics(results):
    total = len(results)
    success_count = sum(1 for r in results if r["success"])
    fail_count = total - success_count
    latencies = [r["latency"] for r in results if r["success"]]
    avg_latency = statistics.mean(latencies) if latencies else 0
    total_bytes = success_count * 100.0
    total_time = sum(r["latency"] for r in results)
    throughput = (total_bytes / total_time) if total_time > 0 else 0

    return {
        "total_queries": total,
        "successful_queries": success_count,
        "failed_queries": fail_count,
        "avg_latency_s": round(avg_latency, 4),
        "throughput_Bps": int(throughput)
    }

def progress_bar(prefix, count, total, length=40):
    filled_len = int(round(length * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (length - filled_len)
    sys.stdout.write("\r%s |%s| %s%% (%d/%d)" % (prefix, bar, percents, count, total))
    sys.stdout.flush()
    if count == total:
        sys.stdout.write("\n")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 dns_pcap_client.py <pcap_file> <resolver_ip> [port]", file=sys.stderr)
        sys.exit(1)

    pcap_file = sys.argv[1]
    resolver_ip = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 53

    print("Reading queries from:", pcap_file)
    domains = extract_domains_from_pcap(pcap_file)
    if not domains:
        print("No valid DNS queries found.")
        sys.exit(0)
    print("Found %d unique queries." % len(domains))

    results = []
    total = len(domains)
    for count, domain in enumerate(domains, 1):
        latency, success = send_query_with_dig(domain, resolver_ip, port)
        results.append({"latency": latency, "success": success})
        progress_bar("Querying", count, total)

    metrics = compute_metrics(results)
    print("\n--- Metrics Summary ---")
    for k, v in metrics.items():
        print("%s: %s" % (k, v))

if __name__ == "__main__":
    main()
