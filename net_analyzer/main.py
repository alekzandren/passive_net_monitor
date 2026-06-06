import logging
from scapy.all import sniff, conf
from net_analyzer.analyzer.parser import PacketParser
from net_analyzer.analyzer.stats_manager import StatsManager

logger = logging.getLogger(__name__)

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
        self.interface = interface
        self.stats = stats_manager
        self.parser = PacketParser()
        self._running = False

    def _process_packet(self, packet):
        """
        Внутренний колбэк для обработки каждого пакета.
        Вызывается Scapy в реальном времени.
        """
        try:
            packet_data = self.parser.extract_info(packet)

            if packet_data and self.stats:
                self.stats.update(packet_data)

        except Exception:
            logger.exception("Ошибка при обработке пакета")

    def start(self):
        """
        Запуск цикла прослушивания сети.
        """
        self._running = True
        current_iface = self.interface or conf.iface
        logger.info(f"Запуск сниффера на интерфейсе: {current_iface}")

        sniff(
            iface=current_iface,
            prn=self._process_packet,
            store=0,
            filter="ip",
            stop_filter=lambda p: not self._running
        )

    def stop(self):
        """
        Остановка прослушивания сети.
        """
        if self._running:
            self._running = False
            logger.info("Сниффер остановлен.")
