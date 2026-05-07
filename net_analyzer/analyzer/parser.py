from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import Optional, Dict, Any


class PacketParser:
    """Класс для глубокого анализа сетевых пакетов."""

    def __init__(self):
        self.proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def extract_info(self, packet) -> Optional[Dict[str, Any]]:
        """
        Извлекает ключевую информацию из пакета.
        Возвращает словарь с данными или None, если пакет не содержит IP уровня.
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet.getlayer(IP)
        data = {
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "size": len(packet),
            "proto": self.proto_map.get(ip_layer.proto, f"Other({ip_layer.proto})"),
            "app_proto": "Unknown",
            "is_encrypted": False,
            "payload_preview": ""
        }

        if packet.haslayer(TCP):
            self._analyze_tcp(packet, data)
        elif packet.haslayer(UDP):
            self._analyze_udp(packet, data)
        elif packet.haslayer(ICMP):
            data["app_proto"] = "Control Message"

        return data

    def _analyze_tcp(self, packet, data: Dict):
        """DPI анализ для TCP трафика."""
        tcp_layer = packet.getlayer(TCP)
        port = tcp_layer.dport if tcp_layer.dport < tcp_layer.sport else tcp_layer.sport

        if port == 80:
            data["app_proto"] = "HTTP"
            data["is_encrypted"] = False
        elif port == 443:
            data["app_proto"] = "HTTPS"
            data["is_encrypted"] = True
        elif port == 22:
            data["app_proto"] = "SSH"
            data["is_encrypted"] = True

        if packet.haslayer(Raw):
            payload = str(packet.getlayer(Raw).load)
            if "GET" in payload or "POST" in payload:
                data["app_proto"] = "HTTP (Method Detected)"

    def _analyze_udp(self, packet, data: Dict):
        """DPI анализ для UDP трафика."""
        udp_layer = packet.getlayer(UDP)
        port = udp_layer.dport if udp_layer.dport < udp_layer.sport else udp_layer.sport

        if port == 53:
            data["app_proto"] = "DNS"
        elif port in [67, 68]:
            data["app_proto"] = "DHCP"
        elif port == 443:
            data["app_proto"] = "QUIC (HTTPS Over UDP)"
            data["is_encrypted"] = True