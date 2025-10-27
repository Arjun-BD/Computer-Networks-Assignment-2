#!/usr/bin/env python3
# Part A only: build the topology shown in the figure and demonstrate connectivity (pingAll).
# Save as part_a_topo.py and run as root (Mininet requires root).

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
import time

class CustomTopo(Topo):
    def build(self):
        # switches
        s1, s2, s3, s4 = [self.addSwitch('s{}'.format(i)) for i in range(1, 5)]

        # hosts with IPs
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        # common link params
        common_params = {'cls': TCLink, 'bw': 100}   # 100 Mbps

        # host to switch links (2 ms delay)
        self.addLink(h1, s1, **common_params, delay='2ms')
        self.addLink(h2, s2, **common_params, delay='2ms')
        self.addLink(h3, s3, **common_params, delay='2ms')
        self.addLink(h4, s4, **common_params, delay='2ms')

        # chain of switches with specified delays between them
        self.addLink(s1, s2, **common_params, delay='5ms')
        self.addLink(s2, s3, **common_params, delay='8ms')
        self.addLink(s3, s4, **common_params, delay='10ms')

        # connect DNS resolver to s2 with 1 ms delay
        self.addLink(s2, dns, **common_params, delay='1ms')


def run_part_a():
    """Start Mininet with the topology and run pingAll to demonstrate connectivity."""
    setLogLevel('info')
    topo = CustomTopo()
    net = Mininet(topo=topo, link=TCLink)
    try:
        net.start()
        print("\n--- Part A: Testing Connectivity (pingAll) ---")
        # wait a moment for interfaces to come up
        time.sleep(1)
        net.pingAll()
    finally:
        net.stop()


if __name__ == '__main__':
    run_part_a()