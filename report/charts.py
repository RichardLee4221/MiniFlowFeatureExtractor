import matplotlib.pyplot as plt
from collections import Counter


class Visualizer:

    def __init__(self, flows):
        self.flows = flows

    def draw_protocol_distribution(self):

        protocols = []

        for flow in self.flows:
            protocols.append(flow.protocol_name())

        counter = Counter(protocols)

        labels = list(counter.keys())
        values = list(counter.values())

        plt.figure(figsize=(6, 6))
        plt.pie(values, labels=labels, autopct='%1.1f%%')
        plt.title("Protocol Distribution")
        plt.savefig("protocol_distribution.png")

    def draw_packet_timeline(self):

        x = []
        y = []

        index = 0

        for flow in self.flows:

            for ts in flow.timestamps:
                x.append(ts)
                y.append(index)

            index += 1

        plt.figure(figsize=(10, 5))
        plt.scatter(x, y)
        plt.title("Packet Timeline")
        plt.savefig("packet_timeline.png")

    def draw_flow_duration(self):

        durations = []

        for flow in self.flows:
            durations.append(flow.duration())

        plt.figure(figsize=(10, 5))
        plt.hist(durations)
        plt.title("Flow Duration")
        plt.savefig("flow_duration.png")