from scapy.all import sniff
from net_analyzer.analyzer.parser import PacketParser
from net_analyzer.analyzer.stats_manager import StatsManager

class NetworkSniffer:
    def __init__(self, interface: str):
        self.interface = interface
        self.stats = StatsManager()
        self.parser = PacketParser()

    def _process_packet(self, packet):
        data = self.parser.extract_info(packet)
        if data:
            self.stats.update(data['src'], data['size'])
            self.stats.log_to_file(data)

    def start(self):
        print(f"[*] Starting capture on {self.interface}...")
        sniff(iface=self.interface, prn=self._process_packet, store=0)