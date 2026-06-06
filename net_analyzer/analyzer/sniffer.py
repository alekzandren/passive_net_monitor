import queue
import threading
import sys
from scapy.all import sniff, conf
from net_analyzer.analyzer.parser import PacketParser
from net_analyzer.analyzer.stats_manager import StatsManager


class NetworkSniffer:
    """
    Класс для управления захватом трафика.
    Связывает низкоуровневый перехват Scapy с парсером и менеджером статистики.
    """

    def __init__(self, interface: str = None):
        """
        :param interface: Имя сетевого интерфейса (например, 'eth0', 'Wi-Fi').
                          Если None, используется интерфейс по умолчанию.
        """
        self.interface = interface
        self.stats = StatsManager()
        self.parser = PacketParser()
        self.packet_queue = queue.Queue()
        self._running = False
        self._worker_thread = None

    def _process_packet(self, packet):
        """
        Внутренний колбэк для каждого пакета. Вызывается Scapy.
        Должен отрабатывать максимально быстро, чтобы избежать дропа пакетов.
        """
        try:
            data = self.parser.extract_info(packet)
            if data:
                self.packet_queue.put(data)
        except Exception as e:
            print(f"[!] Ошибка при первичном разборе пакета: {e}", file=sys.stderr)

    def _io_worker(self):
        """
        Фоновый воркер, который спокойно забирает данные из очереди,
        обновляет статистику и пишет логи на диск, не тормозя захват трафика.
        """
        while self._running or not self.packet_queue.empty():
            try:
                data = self.packet_queue.get(timeout=1.0)

                self.stats.update(data['src'], data['size'])
                self.stats.log_to_file(data)

                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[!] Ошибка воркера при сохранении статистики: {e}", file=sys.stderr)

    def start(self):
        """
        Запуск сниффера и фонового потока обработки данных.
        """
        self._running = True

        self._worker_thread = threading.Thread(target=self._io_worker, daemon=True)
        self._worker_thread.start()

        current_iface = self.interface or conf.iface
        print(f"[*] Starting capture on {current_iface}...")

        try:
            sniff(
                iface=current_iface,
                prn=self._process_packet,
                store=0,
                filter="ip",
                stop_filter=lambda p: not self._running
            )
        except Exception as e:
            print(f"[!] Критическая ошибка в цикле sniff: {e}", file=sys.stderr)
            self.stop()

    def stop(self):
        """
        Безопасная остановка сниффера с гарантией сохранения всех данных из очереди.
        """
        if self._running:
            print("\n[*] Stopping capture...")
            self._running = False

            if self._worker_thread:
                self._worker_thread.join()

            print("[*] Capture stopped cleanly. All data saved.")
