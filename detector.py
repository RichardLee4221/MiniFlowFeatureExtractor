import numpy as np
                if hasattr(pkt, "flags"):
                    flags = pkt.flags

                    if flags & 0x02:
                        syn_count += 1

            if syn_count > 100:
                print(f"[!] Possible SYN Flood: {flow.src_ip}")

    def detect_port_scan(self):

        print("\n[+] Port Scan Detection")

        source_map = {}

        for flow in self.flows:

            if flow.src_ip not in source_map:
                source_map[flow.src_ip] = set()

            source_map[flow.src_ip].add(flow.dport)

        for ip, ports in source_map.items():

            if len(ports) > 20:
                print(f"[!] Possible Port Scan: {ip}")

    def detect_beacon(self):

        print("\n[+] Beacon Detection")

        for flow in self.flows:

            iats = flow.iat()

            if len(iats) < 5:
                continue

            variance = np.var(iats)

            if variance < 0.00001:
                print(f"[!] Beaconing Detected: {flow.src_ip}")

    def detect_large_transfer(self):

        print("\n[+] Large Transfer Detection")

        for flow in self.flows:

            total = flow.total_bytes()

            if total > 10000000:
                print(f"[!] Large Transfer: {flow.src_ip}")

    def detect_dns_flood(self):

        print("\n[+] DNS Flood Detection")

        for flow in self.flows:

            if flow.dport == 53 and flow.packet_count() > 200:
                print(f"[!] High Frequency DNS Query: {flow.src_ip}")

    def run_all(self):

        self.detect_syn_flood()
        self.detect_port_scan()
        self.detect_beacon()
        self.detect_large_transfer()
        self.detect_dns_flood()