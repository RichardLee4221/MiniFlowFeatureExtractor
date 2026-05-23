import numpy as np
        return upload / (flow.packet_count() + 1)

    def extract_flags(self, flow):

        syn = 0
        ack = 0
        fin = 0
        rst = 0

        for pkt in flow.packets:

            if hasattr(pkt, "flags"):
                flags = pkt.flags

                if flags & 0x02:
                    syn += 1

                if flags & 0x10:
                    ack += 1

                if flags & 0x01:
                    fin += 1

                if flags & 0x04:
                    rst += 1

        return syn, ack, fin, rst

    def run(self):

        for flow in self.flows:

            syn, ack, fin, rst = self.extract_flags(flow)

            item = {
                "src": flow.src_ip,
                "dst": flow.dst_ip,
                "sport": flow.sport,
                "dport": flow.dport,
                "proto": flow.protocol_name(),
                "packets": flow.packet_count(),
                "bytes": flow.total_bytes(),
                "duration": flow.duration(),
                "avg_len": flow.avg_length(),
                "min_len": flow.min_length(),
                "max_len": flow.max_length(),
                "iat_mean": self.extract_iat_mean(flow),
                "iat_std": self.extract_iat_std(flow),
                "entropy": self.extract_packet_entropy(flow),
                "burst": self.extract_burst(flow),
                "ratio": self.extract_ratio(flow),
                "syn": syn,
                "ack": ack,
                "fin": fin,
                "rst": rst
            }

            self.results.append(item)

    def print_summary(self):

        for item in self.results:

            print("=" * 60)
            print(f"Flow: {item['src']} -> {item['dst']}")
            print(f"Protocol: {item['proto']}")
            print(f"Packets: {item['packets']}")
            print(f"Bytes: {item['bytes']}")
            print(f"Duration: {item['duration']:.4f}")
            print(f"Avg Length: {item['avg_len']:.2f}")
            print(f"Entropy: {item['entropy']:.4f}")
            print(f"Burst: {item['burst']}")
            print(f"IAT Mean: {item['iat_mean']:.6f}")
            print(f"SYN: {item['syn']}")
            print(f"ACK: {item['ack']}")
            print(f"RST: {item['rst']}")

    def export_features(self):
        return self.results