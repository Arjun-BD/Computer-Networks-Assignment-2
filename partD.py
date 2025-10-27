#!/usr/bin/env python3
import os
import time
import sys
import subprocess
import statistics
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.nodelib import NAT
from mininet.cli import CLI

EXTERNAL_DNS_IP = '10.0.0.5'
NAT_IP = '10.0.0.254'

def progress_bar(label, n, total):
    steps = 20
    percent = int((n / total) * 100) if total else 0
    filled = int(steps * n / total) if total else 0
    bar = "#" * filled + "-" * (steps - filled)
    sys.stdout.write("\r%s [%s] %d%%" % (label, bar, percent))
    sys.stdout.flush()
    if n >= total:
        sys.stdout.write("\n")

def run_queries(host, resolver_ip, pcap_file):
    results = []
    domains = []
    
    info("\nExtracting unique domains from {} using TShark...".format(pcap_file))
    
    try:
        subprocess.run(['tshark', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
    except FileNotFoundError:
        info("\nERROR: TShark command not found. Please install TShark (Wireshark command-line utility) to proceed.\n")
        return results
    except subprocess.CalledProcessError:
        info("\nERROR: TShark installed but failed to run. Check your installation.\n")
        return results
    except subprocess.TimeoutExpired:
        info("\nERROR: TShark check timed out.\n")
        return results
    
    try:
        tshark_cmd = [
            'tshark', 
            '-r', pcap_file,
            '-Y', 'dns.flags.response == 0 && dns.qry.name',
            '-T', 'fields',
            '-e', 'dns.qry.name'
        ]
        
        tshark_process = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        
        tshark_output_stdout = tshark_process.stdout.decode('utf-8')
        raw_domains = tshark_output_stdout.splitlines()
        
        seen_domains = set()
        for domain in raw_domains:
            cleaned_domain = domain.strip().strip('.')
            if cleaned_domain and cleaned_domain not in seen_domains:
                domains.append(cleaned_domain)
                seen_domains.add(cleaned_domain)
        
    except FileNotFoundError: 
        info("\nWARNING: PCAP file '{}' not found. Skipping queries for {}.\n".format(pcap_file, host.name))
        return results
    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode('utf-8').strip() if e.stderr else "Unknown TShark error."
        info("\nERROR running TShark on PCAP file: {}\n".format(error_message))
        return results
    except Exception as e:
        info("\nGENERAL ERROR processing PCAP file: {}\n".format(e))
        return results

    total = len(domains)
    count = 0
    
    info("Found {} unique queries in {}.\n".format(total, pcap_file))

    for domain in domains:
        start = time.time()
        ret = host.cmd("dig +time=2 @%s %s +short" % (resolver_ip, domain))
        info("%s dig output for %s: %s\n" % (host.name, domain, ret.strip()))
        end = time.time()
        latency = end - start
        
        success = 1 if ret.strip() and not ("connection timed out" in ret.lower()) else 0
        
        results.append({"latency": latency, "success": success})
        count += 1
        progress_bar("Queries from %s" % host.name, count, total)
            
    return results

def compute_metrics(results):
    total_queries = len(results)
    successful = sum(r["success"] for r in results)
    failed = total_queries - successful
    latencies = [r["latency"] for r in results if r["success"]]
    avg_latency = statistics.mean(latencies) if latencies else 0
    
    total_bytes = successful * 100 
    total_time = sum([r["latency"] for r in results])
    throughput = total_bytes / total_time if total_time > 0 else 0

    return {"total_queries": total_queries,
            "successful_queries": successful,
            "failed_queries": failed,
            "avg_latency_s": round(avg_latency, 4),
            "throughput_Bps": int(throughput)}

def run_experiment():
    net = None
    metrics = {}
    gateway_ip = NAT_IP

    try:
        net = Mininet(controller=OVSController, link=TCLink)
        net.addController('c0', controller=OVSController)

        s1 = net.addSwitch('s1')
        s2 = net.addSwitch('s2')
        s3 = net.addSwitch('s3')
        s4 = net.addSwitch('s4')

        gateway_ip_cidr = '%s/24' % gateway_ip
        info("--- Adding NAT Gateway ({}) to s1 for Internet Access ---\n".format(gateway_ip))
        nat = net.addNAT(ip=gateway_ip_cidr, connect=s1)
        nat.configDefault()

        hosts = {}
        info("--- Adding hosts with IP/Mask and default route via {} ---\n".format(gateway_ip))
        
        default_route = 'via %s' % gateway_ip
        
        hosts['h1'] = net.addHost('h1', ip='10.0.0.1/24', defaultRoute=default_route)
        hosts['h2'] = net.addHost('h2', ip='10.0.0.2/24', defaultRoute=default_route)
        hosts['h3'] = net.addHost('h3', ip='10.0.0.3/24', defaultRoute=default_route)
        hosts['h4'] = net.addHost('h4', ip='10.0.0.4/24', defaultRoute=default_route)
        hosts['h5'] = net.addHost('h5', ip='10.0.0.5/24', defaultRoute=default_route)

        net.addLink(hosts['h1'], s1, bw=100, delay='2ms')
        net.addLink(hosts['h2'], s2, bw=100, delay='2ms')
        net.addLink(hosts['h5'], s2, bw=100, delay='1ms') 
        net.addLink(hosts['h3'], s3, bw=100, delay='2ms')
        net.addLink(hosts['h4'], s4, bw=100, delay='2ms')
        
        net.addLink(s1, s2, bw=100, delay='5ms')
        net.addLink(s2, s3, bw=100, delay='8ms')
        net.addLink(s3, s4, bw=100, delay='10ms')

        net.start()
        
        dns_ip = EXTERNAL_DNS_IP
        client_hosts = [hosts[h] for h in ['h1', 'h2', 'h3', 'h4']]
        
        info("\n--- Configuring clients (h1-h4) to use Custom DNS {}...\n".format(dns_ip))
        
        for h in client_hosts:
            h.cmd('echo "nameserver {}" > /etc/resolv.conf'.format(dns_ip))
        # print("--- DNS Server Output on h5 ---")
        # # hosts['h5'].cmd("nohup sudo python3 custom_dns_resolver.py 53535 > ~/resolver.log 2>&1 &")
        # output = hosts['h5'].cmd("sudo python3 custom_dns_resolver.py 53535")
        # print(output)
        # time.sleep(2)
        info("\n--- Starting custom DNS server on h5 ---\n")
        # hosts['h5'].cmd("pkill -f custom_dns_resolver.py")  # clean any old instances
        # CLI(net)
        # hosts['h5'].cmd("nohup python3 custom_dns_resolver.py 53535 > /tmp/resolver.log 2>&1 &")
        time.sleep(2)  # give it a moment to start

        # Check if server started
        lsof_output = hosts['h5'].cmd("lsof -iUDP:53535 | grep LISTEN")
        if lsof_output.strip():
            info("[*] DNS server is now listening on UDP 53535:\n%s\n" % lsof_output.strip())
        else:
            info("[x] DNS server failed to start. Check log:\n")
            log_output = hosts['h5'].cmd("cat /tmp/resolver.log")
            info(log_output)
            sys.exit(1)
        # Check if the process is running
        ps_output = hosts['h5'].cmd("ps aux | grep '[c]ustom_dns_resolver.py'")
        if not ps_output.strip():
            info("[x] ERROR: DNS server failed to start on h5. Check ~/resolver.log\n")
            return  # or sys.exit(1)
        else:
            info("[*] DNS server successfully started on h5.\n")

        output = hosts['h1'].cmd('dig @10.0.0.5 -p 53535 wpad +short')
        print(output)

        info("\n*** Starting DNS queries against Custom DNS ({})...\n".format(dns_ip))
        
        for h in client_hosts:
            pcap_file_name = "%s_dns.pcap" % h.name
            results = run_queries(h, dns_ip, pcap_file_name)
            
            if results:
                metrics[h.name] = compute_metrics(results)
            else:
                metrics[h.name] = {"message": "No data (PCAP not found or extraction failed)"}
            break
        
        info("\n=== DNS PERFORMANCE SUMMARY ===\n")
        for host, vals in metrics.items():
            info("%s : %s\n" % (host, str(vals)))

    except Exception as e:
        info("An error occurred during experiment: {}\n".format(e))
    finally:
        if net:
            
            net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run_experiment()
