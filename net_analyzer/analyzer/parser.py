from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import Optional, Dict, Any


class PacketParser:
    """Класс для глубокого анализа сетевых пакетов."""

    def __init__(self):
        self.proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.tcp_port_map = {80: "HTTP", 443: "HTTPS", 22: "SSH"}
        self.udp_port_map = {53: "DNS", 67: "DHCP", 68: "DHCP"}

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

        tcp_layer = packet.getlayer(TCP)
        udp_layer = packet.getlayer(UDP)
        icmp_layer = packet.getlayer(ICMP)

        if tcp_layer:
            self._analyze_tcp(tcp_layer, data)
        elif udp_layer:
            self._analyze_udp(udp_layer, data)
        elif icmp_layer:
            data["app_proto"] = "Control Message"

        raw_layer = packet.getlayer(Raw)
        if raw_layer:
            self._analyze_raw_payload(raw_layer.load, data)

        return data

    def _analyze_tcp(self, tcp_layer, data: Dict):
        """DPI анализ для TCP трафика."""
        port = tcp_layer.dport if tcp_layer.dport in self.tcp_port_map else tcp_layer.sport

        if port in self.tcp_port_map:
            data["app_proto"] = self.tcp_port_map[port]
            if port in [443, 22]:
                data["is_encrypted"] = True

    def _analyze_udp(self, udp_layer, data: Dict):
        """DPI анализ для UDP трафика."""
        port = udp_layer.dport if udp_layer.dport in self.udp_port_map else udp_layer.sport

        if port in self.udp_port_map:
            data["app_proto"] = self.udp_port_map[port]

    def _analyze_raw_payload(self, raw_bytes: bytes, data: Dict):
        """Анализ полезной нагрузки и извлечение сигнатур."""
        if b"GET " in raw_bytes or b"POST " in raw_bytes:
            data["app_proto"] = "HTTP (Method Detected)"
            data["is_encrypted"] = False
            
        data["payload_preview"] = raw_bytes[:64].decode('utf-8', errors='replace')
