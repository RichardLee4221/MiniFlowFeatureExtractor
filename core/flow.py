class Flow:

    def __init__(self, key):
        self.key = key
        self.packets = []
        self.timestamps = []
        self.lengths = []
        self.protocol = None
        self.src_ip = key[0]
        self.dst_ip = key[1]
        self.sport = key[2]
        self.dport = key[3]
        self.proto = key[4]

    def add_packet(self, pkt):
        self.packets.append(pkt)
        self.timestamps.append(float(pkt.time))
        self.lengths.append(len(pkt))

    def packet_count(self):
        return len(self.packets)

    def duration(self):
        if len(self.timestamps) <= 1:
            return 0
        return max(self.timestamps) - min(self.timestamps)

    def total_bytes(self):
        return sum(self.lengths)

    def avg_length(self):
        if not self.lengths:
            return 0
        return sum(self.lengths) / len(self.lengths)

    def min_length(self):
        if not self.lengths:
            return 0
        return min(self.lengths)

    def max_length(self):
        if not self.lengths:
            return 0
        return max(self.lengths)

    def iat(self):
        if len(self.timestamps) <= 1:
            return [0]

        result = []

        for i in range(1, len(self.timestamps)):
            result.append(self.timestamps[i] - self.timestamps[i - 1])

        return result

    def protocol_name(self):
        if self.proto == 6:
            return "TCP"
        elif self.proto == 17:
            return "UDP"
        else:
            return "OTHER"

    def summary(self):
        return {
            "src": self.src_ip,
            "dst": self.dst_ip,
            "sport": self.sport,
            "dport": self.dport,
            "proto": self.protocol_name(),
            "packets": self.packet_count(),
            "duration": self.duration(),
            "bytes": self.total_bytes()
        }
