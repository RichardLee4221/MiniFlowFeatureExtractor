from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
from core.flow import Flow


def parse_pcap(file_path):

    packets = rdpcap(file_path)

    flows = {}

    for pkt in packets:

        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto

        sport = 0
        dport = 0

        if TCP in pkt or UDP in pkt:
            sport = pkt.sport
            dport = pkt.dport

        key = (src, dst, sport, dport, proto)

        if key not in flows:
            flows[key] = Flow(key)

        flows[key].add_packet(pkt)

    return list(flows.values())