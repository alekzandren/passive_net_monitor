from scapy.all import sniff, conf
from net_analyzer.analyzer.parser import PacketParser
from net_analyzer.analyzer.stats_manager import StatsManager


class NetworkSniffer:
    """
    Класс для управления захватом трафика.
    Связывает низкоуровневый перехват Scapy с парсером и менеджером статистики.
    """

    def __init__(self, interface: str = None, stats_manager: StatsManager = None):
        """
        :param interface: Имя сетевого интерфейса (например, 'eth0', 'Wi-Fi').
                          Если None, используется интерфейс по умолчанию.
        :param stats_manager: Экземпляр StatsManager для сохранения данных.
        """
        self.interface = interface or conf.iface
        self.stats = stats_manager
        self.parser = PacketParser()

    def _process_packet(self, packet):
        """
        Внутренний колбэк для обработки каждого пакета.
        Вызывается Scapy в реальном времени.
        """
        try:
            packet_data = self.parser.extract_info(packet)

            if packet_data and self.stats:
                self.stats.update(packet_data)

        except Exception as e:
            print(f"[!] Ошибка при обработке пакета: {e}")

    def start(self):
        """
        Запуск бесконечного цикла прослушивания сети.
        """

        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=0,
            filter="ip"
        )

    def stop(self):
        """
        В Scapy штатная остановка sniff из другого потока сложна,
        обычно достаточно завершить поток, в котором запущен старт,
        но для расширения можно реализовать через stop_filter.
        """
        pass