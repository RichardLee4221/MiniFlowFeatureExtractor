import sys
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import numpy as np


def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    flows = defaultdict(list)

    # 1. 按五元组聚合流 (Directional Flow)
    for pkt in packets:
        if IP in pkt:
            proto = pkt[IP].proto
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            sport, dport = (pkt.sport, pkt.dport) if (TCP in pkt or UDP in pkt) else (0, 0)

            # 五元组作为 Key
            flow_key = (src_ip, dst_ip, sport, dport, proto)
            flows[flow_key].append(pkt)

    print(f"{'Flow (Src->Dst)':<45} | {'Pkts':<5} | {'Duration':<8} | {'AvgLen':<7} | {'IAT_Mean'}")
    print("-" * 90)

    for key, flow_pkts in flows.items():
        # --- 基础统计 ---
        pkt_count = len(flow_pkts)
        timestamps = [float(p.time) for p in flow_pkts]
        lengths = [len(p) for p in flow_pkts]

        # 流持续时间
        duration = max(timestamps) - min(timestamps) if pkt_count > 1 else 0

        # 平均包长
        avg_len = sum(lengths) / pkt_count

        # --- 上下行比例计算 ---
        # 寻找反向流 (Dst->Src)
        rev_key = (key[1], key[0], key[3], key[2], key[4])
        up_bytes = sum(lengths)
        down_bytes = sum([len(p) for p in flows.get(rev_key, [])])
        ratio = up_bytes / down_bytes if down_bytes > 0 else float('inf')

        # --- Inter-arrival Time (IAT) ---
        iats = np.diff(timestamps) if pkt_count > 1 else [0]
        iat_mean = np.mean(iats)

        # --- Burst 特征 (简单定义：100ms内连续发包的最大数量) ---
        burst_threshold = 0.1
        current_burst = 1
        max_burst = 1
        for i in range(len(iats)):
            if iats[i] < burst_threshold:
                current_burst += 1
            else:
                max_burst = max(max_burst, current_burst)
                current_burst = 1
        max_burst = max(max_burst, current_burst)

        # --- TCP Flag 统计 ---
        flags_count = defaultdict(int)
        if key[4] == 6:  # TCP
            for p in flow_pkts:
                if TCP in p:
                    f = p[TCP].flags
                    flags_count['SYN'] += 1 if f & 0x02 else 0
                    flags_count['ACK'] += 1 if f & 0x10 else 0
                    flags_count['FIN'] += 1 if f & 0x01 else 0
                    flags_count['RST'] += 1 if f & 0x04 else 0

        # 输出结果
        flow_str = f"{key[0]}:{key[2]} -> {key[1]}:{key[3]}"
        print(f"{flow_str:<45} | {pkt_count:<5} | {duration:<8.4f} | {avg_len:<7.1f} | {iat_mean:.4f}")
        if key[4] == 6:
            print(f"  [Flags] SYN:{flags_count['SYN']} ACK:{flags_count['ACK']} RST:{flags_count['RST']}")
        print(f"  [Ratio] Up/Down Byte Ratio: {ratio:.2f} | [Burst] Max Packets in 100ms: {max_burst}")
        print("-" * 90)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_feature_extractor.py <file.pcap>")
    else:
        extract_features(sys.argv[1])