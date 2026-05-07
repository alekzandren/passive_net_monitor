import threading
import time
from collections import defaultdict
from typing import Dict, Any


class StatsManager:
    def __init__(self, log_file: str = "network_traffic.log"):
        self.log_file = log_file
        self._stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "protocols": set()})
        self._lock = threading.Lock()

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"--- Traffic Log Started: {time.ctime()} ---\n")

    def update(self, packet_info: Dict[str, Any]):
        """Обновление глобальной статистики из данных парсера."""
        src_ip = packet_info["src"]
        size = packet_info["size"]
        proto = packet_info["app_proto"]

        with self._lock:
            self._stats[src_ip]["bytes"] += size
            self._stats[src_ip]["packets"] += 1
            self._stats[src_ip]["protocols"].add(proto)

        self._log_to_file(packet_info)

    def _log_to_file(self, info: Dict[str, Any]):
        """Запись каждой транзакции в файл."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{timestamp}] {info['src']} -> {info['dst']} | "
            f"Proto: {info['proto']}/{info['app_proto']} | "
            f"Size: {info['size']} bytes | Encrypted: {info['is_encrypted']}\n"
        )
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)

    def get_snapshot(self) -> Dict:
        """Возвращает копию текущей статистики для вывода."""
        with self._lock:
            return dict(self._stats)