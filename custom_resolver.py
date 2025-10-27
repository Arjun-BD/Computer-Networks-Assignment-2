#!/usr/bin/env python3
import sys
import socket
import time
from datetime import datetime
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1

ROOT_SERVER_IP = "198.41.0.4"  # A.ROOT-SERVERS.NET
CACHE_TTL_SECONDS = 3600  # 1 hour TTL
LOG_FILE = "resolver.log"

# --- Logging and Caching Classes ---

class DnsLog:
    def __init__(self, log_file):
        self.log_entries = []
        self.plot_data = {}
        self.unique_domains_resolved_count = 0
        self.max_domains_for_plot = 10
        self.log_filename = log_file
        with open(self.log_filename, 'w', encoding='utf-8') as f:
            f.write("DNS Resolver Log Started: %s\n" % datetime.now().isoformat())

    def log_step(self, timestamp, domain, mode, server_ip, step, response_referral, rtt, total_time, cache_status="N/A"):
        entry = {
            'timestamp': timestamp.isoformat(),
            'domain_name': domain,
            'resolution_mode': mode,
            'dns_server_ip': server_ip,
            'step_of_resolution': step,
            'response_or_referral': response_referral,
            'round_trip_time': "%.4fs" % rtt,
            'total_time_to_resolution': "%.4fs" % total_time if total_time is not None else "N/A",
            'cache_status': cache_status
        }
        self.log_entries.append(entry)
        with open(self.log_filename, 'a', encoding='utf-8') as f:
            f.write("%s\n" % str(entry))

    def record_plot_data(self, domain, total_servers, total_latency):
        if domain not in self.plot_data and self.unique_domains_resolved_count < self.max_domains_for_plot:
            self.unique_domains_resolved_count += 1
            self.plot_data[domain] = {
                'total_servers_visited': total_servers,
                'total_latency': total_latency
            }

    def print_plot_summary(self):
        print("\n" + "="*50)
        print("Summary Data for Plotting (First 10 Unique URLs)")
        print("="*50)
        for i, (domain, data) in enumerate(self.plot_data.items()):
            print("[%d] %s: Servers=%d, Latency=%.4fs" % (i+1, domain, data['total_servers_visited'], data['total_latency']))
        print("="*50)
        print("Logs also saved to resolver.log")


class DnsCache:
    def __init__(self):
        self.cache = {}

    def get(self, domain):
        if domain in self.cache:
            ip, cached_time = self.cache[domain]
            if (time.time() - cached_time) < CACHE_TTL_SECONDS:
                return ip, "HIT"
            else:
                del self.cache[domain]
        return None, "MISS"

    def set(self, domain, ip):
        self.cache[domain] = (ip, time.time())

dns_log = DnsLog(LOG_FILE)
dns_cache = DnsCache()


# --- Resolution Logic ---

def get_step_type(current_ip):
    if current_ip == ROOT_SERVER_IP:
        return "Root"
    elif current_ip.split('.')[-1].isdigit():
        return "TLD/Authoritative"
    return "Unknown"


def resolve_iteratively(domain, original_domain=None, depth=0, max_depth=10):
    if depth > max_depth:
        print("[x] Maximum recursion depth reached for %s" % domain)
        return None

    if original_domain is None:
        original_domain = domain

    total_start_time = time.time()
    ip_from_cache, cache_status = dns_cache.get(domain)
    if ip_from_cache:
        total_latency = time.time() - total_start_time
        timestamp = datetime.now()
        dns_log.log_step(timestamp, domain, "Iterative (Cached)", "N/A", "Cache", "Answer: %s" % ip_from_cache, 0.0, total_latency, cache_status)
        dns_log.record_plot_data(domain, 1, total_latency)
        print("[*] Cache HIT for %s: %s" % (domain, ip_from_cache))
        return IP(dst="127.0.0.1") / UDP(dport=53) / DNS(an=DNSRR(rrname=domain, type=1, rdata=ip_from_cache))

    current_ns_ip = ROOT_SERVER_IP
    servers_visited = 0
    print("\n[+] Starting iterative resolution for %s (Cache MISS)" % domain)

    for hop in range(max_depth):
        step_start_time = time.time()
        query = IP(dst=current_ns_ip) / UDP(dport=53) / DNS(rd=0, qd=DNSQR(qname=domain))
        resp = sr1(query, verbose=0, timeout=2)
        rtt = time.time() - step_start_time
        timestamp = datetime.now()
        servers_visited += 1
        step_type = get_step_type(current_ns_ip)
        response_referral = "Timeout or invalid response"
        next_ip = current_ns_ip

        if not resp or not resp.haslayer(DNS):
            dns_log.log_step(timestamp, domain, "Iterative (Query Failed)", current_ns_ip, step_type, response_referral, rtt, None, "MISS")
            print("[x] Timeout or invalid response from %s" % current_ns_ip)
            return None

        dns_resp = resp[DNS]

        # Check Answer
        if dns_resp.an:
            answers = [rr.rdata for rr in dns_resp.an if rr.type == 1]
            if answers:
                final_ip = answers[0]
                total_latency = time.time() - total_start_time
                response_referral = "Answer: %s" % final_ip
                dns_log.log_step(timestamp, domain, "Iterative (Resolved)", current_ns_ip, "Authoritative", response_referral, rtt, total_latency, "MISS")
                dns_cache.set(domain, final_ip)
                dns_log.record_plot_data(domain, servers_visited, total_latency)
                print("[*] Final Answer(s) for %s: %s" % (domain, answers))
                return dns_resp

        # Check Authority (NS)
        ns_names = []
        if dns_resp.ns:
            for rr in dns_resp.ns:
                try:
                    if rr.type == 2:
                        ns_names.append(rr.rdata.decode())
                except Exception:
                    continue

        if ns_names:
            glue_ip = None
            if dns_resp.ar:
                for rr in dns_resp.ar:
                    if rr.type == 1:
                        glue_ip = rr.rdata
                        break

            if glue_ip:
                next_ip = glue_ip
                response_referral = "Delegation to: %s @ Glue IP: %s" % (', '.join(ns_names), glue_ip)
                print("[>] Delegated to %s @ Glue IP: %s" % (ns_names[0], glue_ip))
            else:
                fallback_ns = ns_names[0]
                # Prevent infinite recursion on original domain
                if fallback_ns == original_domain:
                    print("[x] Cannot resolve NS %s for original domain %s (no glue IP)" % (fallback_ns, original_domain))
                    dns_log.log_step(timestamp, domain, "Iterative (Failed delegation)", current_ns_ip, step_type,
                                     "No glue IP and NS same as original domain", rtt, None, "MISS")
                    return None
                # Resolve NS to get its IP
                temp_ns_resp = resolve_iteratively(fallback_ns, original_domain=original_domain, depth=depth+1)
                if temp_ns_resp and temp_ns_resp.an and temp_ns_resp.an[0].type == 1:
                    next_ip = temp_ns_resp.an[0].rdata
                    print("[>] Found NS IP: %s" % next_ip)
                else:
                    response_referral = "Failed to resolve next NS IP: %s" % fallback_ns
                    dns_log.log_step(timestamp, domain, "Iterative (Failed delegation)", current_ns_ip, step_type, response_referral, rtt, None, "MISS")
                    print("[x] Failed to resolve next NS IP")
                    return None

            dns_log.log_step(timestamp, domain, "Iterative (Delegation)", current_ns_ip, step_type, response_referral, rtt, None, "MISS")
            current_ns_ip = next_ip
            continue
        else:
            response_referral = "No authority section for delegation"
            dns_log.log_step(timestamp, domain, "Iterative (Failed delegation)", current_ns_ip, step_type, response_referral, rtt, None, "MISS")
            print("[x] No authority section to continue delegation")
            return None

    # Max hops reached
    total_latency = time.time() - total_start_time
    dns_log.log_step(datetime.now(), domain, "Iterative (Failed)", current_ns_ip, get_step_type(current_ns_ip),
                     "Iteration limit reached", 0.0, total_latency, "MISS")
    print("[x] Iteration limit reached for %s" % domain)
    return None


# --- UDP DNS Server ---

def start_dns_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print("[*] Custom DNS Resolver running on UDP port %d..." % port)

    try:
        while True:
            data, addr = sock.recvfrom(512)
            dns_query = DNS(data)
            if not dns_query or not dns_query.qd:
                continue
            domain = dns_query.qd.qname.decode(errors='ignore').rstrip('.')
            print("\n--- Incoming Query from %s: %s ---" % (addr, domain))
            dns_response = resolve_iteratively(domain)
            if dns_response and dns_response.an:
                answer_pkt = DNS(
                    id=dns_query.id,
                    qr=1, aa=1, ra=0,
                    qd=dns_query.qd,
                    an=dns_response.an
                )
            else:
                answer_pkt = DNS(
                    id=dns_query.id,
                    qr=1, rcode=2,  # SERVFAIL
                    qd=dns_query.qd
                )
            sock.sendto(bytes(answer_pkt), addr)
            print("[<] Sent response to %s" % str(addr))

    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        dns_log.print_plot_summary()
    finally:
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 %s <port>" % sys.argv[0])
        sys.exit(1)
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("Error: Port must be an integer.")
        sys.exit(1)

    start_dns_server(port)
