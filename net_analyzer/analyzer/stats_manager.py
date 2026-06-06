import threading
import time
from collections import defaultdict
from typing import Dict, Any


class StatsManager:
    def __init__(self, log_file: str = "network_traffic.log"):
        self.log_file = log_file
        self._stats = defaultdict(lambda: {"bytes": 0, "packets": 0, "protocols": set()})
        self._lock = threading.Lock()
        self._file = open(self.log_file, "a+", encoding="utf-8", buffering=1)
        self._file.seek(0, 2)
        if self._file.tell() == 0:
            self._file.write(f"--- Traffic Log Started: {time.ctime()} ---\n")

    def update(self, packet_info: Dict[str, Any]):
        """Обновление глобальной статистики и запись в лог."""
        src_ip = packet_info["src"]
        size = packet_info["size"]
        proto = packet_info["app_proto"]
        
        with self._lock:
            self._stats[src_ip]["bytes"] += size
            self._stats[src_ip]["packets"] += 1
            self._stats[src_ip]["protocols"].add(proto)
            self._log_to_file(packet_info)

    def _log_to_file(self, info: Dict[str, Any]):
        """Внутренний метод записи транзакции в удерживаемый файл."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{timestamp}] {info['src']} -> {info['dst']} | "
            f"Proto: {info['proto']}/{info['app_proto']} | "
            f"Size: {info['size']} bytes | Encrypted: {info['is_encrypted']}\n"
        )
        self._file.write(log_entry)

    def get_snapshot(self) -> Dict[str, Any]:
        """
        Возвращает потокобезопасную копию текущей статистики для отображения в UI/CLI.
        Преобразует set() в list() для последующей JSON-сериализации.
        """
        snapshot = {}
        with self._lock:
            for ip, metrics in self._stats.items():
                snapshot[ip] = {
                    "bytes": metrics["bytes"],
                    "packets": metrics["packets"],
                    "protocols": list(metrics["protocols"])
                }
        return snapshot

    def __del__(self):
        """Гарантируем закрытие файла при уничтожении объекта."""
        try:
            self._file.close()
        except Exception:
            pass
