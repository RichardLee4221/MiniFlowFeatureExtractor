import cmd
from core.parser import parse_pcap
from core.features import FeatureExtractor


class FlowShell(cmd.Cmd):

    intro = "FlowScope Interactive Shell"
    prompt = "FlowScope > "

    def __init__(self):
        super().__init__()
        self.flows = []

    def do_load(self, arg):

        self.flows = parse_pcap(arg)

        print(f"Loaded {len(self.flows)} flows")

    def do_show(self, arg):

        if arg == "flows":

            for flow in self.flows:
                print(flow.summary())

    def do_stats(self, arg):

        extractor = FeatureExtractor(self.flows)
        extractor.run()
        extractor.print_summary()

    def do_filter(self, arg):

        tokens = arg.split()

        if len(tokens) < 2:
            return

        mode = tokens[0]
        value = tokens[1]

        if mode == "tcp":

            for flow in self.flows:
                if flow.proto == 6:
                    print(flow.summary())

        elif mode == "udp":

            for flow in self.flows:
                if flow.proto == 17:
                    print(flow.summary())

        elif mode == "ip":

            for flow in self.flows:
                if flow.src_ip == value or flow.dst_ip == value:
                    print(flow.summary())

    def do_exit(self, arg):
        return True

    def do_help(self, arg):

        print("load <pcap>")
        print("show flows")
        print("stats")
        print("filter tcp")
        print("filter udp")
        print("filter ip <addr>")
        print("exit")
