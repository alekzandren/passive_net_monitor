import os
import sys
from scapy.all import conf

class NetworkUtils:
    @staticmethod
    def check_permissions():
        """Проверка прав администратора/root."""
        if os.name != 'nt':
            if os.geteuid() != 0:
                print("[-] КРИТИЧЕСКАЯ ОШИБКА: Запустите скрипт через 'sudo'.")
                sys.exit(1)
        else:
            pass

    @staticmethod
    def format_bytes(size_bytes: int) -> str:
        """Конвертация байтов в читаемый формат (KB, MB, GB)."""
        if size_bytes == 0:
            return "0B"
        units = ("B", "KB", "MB", "GB")
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024
            i += 1
        return f"{size_bytes:.2f} {units[i]}"

    @staticmethod
    def get_available_interfaces():
        """Возвращает список доступных интерфейсов."""
        return conf.ifaces

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