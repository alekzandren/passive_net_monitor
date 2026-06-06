import os
import sys
import math
from scapy.all import conf


class NetworkUtils:
    @staticmethod
    def check_permissions():
        """
        Кроссплатформенная проверка прав администратора/root.
        Завершает работу скрипта, если прав недостаточно.
        """
        if os.name == 'nt':
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = False

            if not is_admin:
                print("[-] КРИТИЧЕСКАЯ ОШИБКА: Запустите командную строку/PowerShell от имени Администратора.")
                sys.exit(1)
        else:
            if os.geteuid() != 0:
                print("[-] КРИТИЧЕСКАЯ ОШИБКА: Запустите скрипт через 'sudo'.")
                sys.exit(1)

    @staticmethod
    def format_bytes(size_bytes: int) -> str:
        """Конвертация байтов в читаемый формат (KB, MB, GB) с высокой точностью."""
        if size_bytes == 0:
            return "0 B"

        units = ("B", "KB", "MB", "GB", "TB")
        i = int(math.floor(math.log(size_bytes, 1024)))

        if i >= len(units):
            i = len(units) - 1

        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {units[i]}"

    @staticmethod
    def get_available_interfaces() -> dict:
        """
        Возвращает отфильтрованный словарь доступных интерфейсов.
        Ключ — понятное имя (Wi-Fi, eth0), значение — системное имя для Scapy.
        """
        interfaces_data = {}

        for iface_name in conf.ifaces:
            iface = conf.ifaces[iface_name]

            if iface.description and "loopback" in iface.description.lower():
                continue

            display_name = iface.name or iface.description
            interfaces_data[display_name] = iface_name

        return interfaces_data

    @staticmethod
    def print_banner():
        """Красивый вывод при старте."""
        banner = """
        ===========================================
        |    ASYNCHRONOUS NETWORK ANALYZER v1.0   |
        |    Role: Security Engineer Pro Mode     |
        ===========================================
        """
        print(banner)
