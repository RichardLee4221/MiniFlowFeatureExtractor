from datetime import datetime


class ReportGenerator:

    def __init__(self, results):
        self.results = results

    def generate_markdown(self):

        content = "# FlowScope Analysis Report\n\n"

        content += f"Generated: {datetime.now()}\n\n"

        for item in self.results:

            content += "---\n"
            content += f"## Flow {item['src']} -> {item['dst']}\n"
            content += f"- Protocol: {item['proto']}\n"
            content += f"- Packets: {item['packets']}\n"
            content += f"- Bytes: {item['bytes']}\n"
            content += f"- Entropy: {item['entropy']}\n"
            content += f"- Burst: {item['burst']}\n"

        with open("report.md", "w") as f:
            f.write(content)

        print("Markdown Report Generated")