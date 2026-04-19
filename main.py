"""
Главный модуль инструментария для работы с сетевыми принтерами.

Содержит классы:
- NetworkScanner: быстрое асинхронное сканирование сети на наличие принтеров (порт 9100).
- ExploitManager: фасад для удобного использования классов из модуля exploits.
- PrinterToolkit: высокоуровневый API, объединяющий сканирование и эксплуатацию.

Также содержит функцию main() с примерами использования.
"""

import asyncio
import socket
import ipaddress
import logging
from typing import Dict, Any, Optional, List
from exploits import DeviceInfoGatherer, DisplayMessageSender


class NetworkScanner:
    """
    Асинхронный сканер сети для обнаружения устройств с открытым портом 9100 (принтеры).
    Использует конкурентные TCP-подключения с малым таймаутом для быстрого сканирования.
    """

    def __init__(self, printer_port: int = 9100):
        """
        Инициализация сканера.

        Параметры:
            printer_port (int): порт для проверки (по умолчанию 9100 — стандартный порт RAW-печати/PJL).
        """
        self.printer_port = printer_port
        self.logger = logging.getLogger(self.__class__.__name__)

    def get_my_ip(self) -> str:
        """
        Определяет собственный IP-адрес в локальной сети.

        Использует трюк с UDP-соединением к публичному DNS (8.8.8.8),
        чтобы получить IP, через который машина выходит в сеть.
        Если не удаётся, используется fallback через hostname.

        Возвращает:
            str: IP-адрес (например, '192.168.1.100').
        """
        try:
            # Создаём UDP-сокет
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Подключаемся к 8.8.8.8:80 (никакие данные не отправляются)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.logger.debug(f"Определён собственный IP: {ip}")
            return ip
        except Exception:
            # Fallback: получаем IP через hostname (может вернуть 127.0.0.1, если несколько интерфейсов)
            ip = socket.gethostbyname(socket.gethostname())
            self.logger.debug(f"Определён IP через hostname: {ip}")
            return ip

    def get_network_range(self, cidr: str = "/24") -> ipaddress.IPv4Network:
        """
        Формирует объект сети на основе собственного IP и указанной маски.

        Пример: если мой IP 192.168.1.100 и cidr '/24', результат: 192.168.1.0/24.

        Параметры:
            cidr (str): маска подсети в нотации CIDR (по умолчанию '/24').

        Возвращает:
            ipaddress.IPv4Network: объект сети.
        """
        my_ip = self.get_my_ip()
        # Заменяем последний октет на 0 и добавляем маску
        network_str = '.'.join(my_ip.split('.')[:-1]) + f'.0{cidr}'
        self.logger.debug(f"Сформирована сеть для сканирования: {network_str}")
        return ipaddress.ip_network(network_str, strict=False)

    async def _check_port(self, ip: str, semaphore: asyncio.Semaphore) -> bool:
        """
        Проверяет, открыт ли порт printer_port на указанном IP.
        Использует семафор для ограничения числа одновременных соединений.

        Параметры:
            ip (str): IP-адрес для проверки.
            semaphore (asyncio.Semaphore): семафор для ограничения конкурентности.

        Возвращает:
            bool: True если порт открыт, иначе False.
        """
        async with semaphore:
            try:
                # Пытаемся открыть соединение с очень маленьким таймаутом (50 мс).
                # В локальной сети этого достаточно, чтобы отличить живой хост от мёртвого.
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, self.printer_port),
                    timeout=0.05
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                # Любая ошибка (таймаут, отказ в соединении и т.д.) означает, что порт недоступен
                return False

    async def scan(self, max_concurrent: int = 200, cidr: str = "/24") -> List[str]:
        """
        Сканирует текущую подсеть (определяемую автоматически) и возвращает список IP с открытым портом.

        Параметры:
            max_concurrent (int): максимальное количество одновременных проверок порта.
            cidr (str): маска подсети.

        Возвращает:
            List[str]: список IP-адресов найденных принтеров.
        """
        network = self.get_network_range(cidr)
        my_ip = self.get_my_ip()
        # Получаем все хосты в сети, исключая собственный IP
        hosts = [str(ip) for ip in network.hosts() if str(ip) != my_ip]

        self.logger.info(f"Запуск сканирования сети {network} (всего хостов: {len(hosts)})")
        print(f"Сканирование сети {network}...")

        # Семафор ограничивает количество одновременных задач, чтобы не перегружать систему
        semaphore = asyncio.Semaphore(max_concurrent)

        # Создаём задачи для всех хостов
        tasks = [self._check_port(host, semaphore) for host in hosts]
        results = await asyncio.gather(*tasks)

        # Отбираем только те IP, для которых проверка вернула True
        printers = [host for host, is_printer in zip(hosts, results) if is_printer]

        self.logger.info(f"Сканирование завершено. Найдено принтеров: {len(printers)}")
        return printers

    async def scan_custom_range(self, network_cidr: str, max_concurrent: int = 200) -> List[str]:
        """
        Сканирует произвольную подсеть, заданную в формате CIDR.

        Параметры:
            network_cidr (str): строка CIDR, например '192.168.1.0/24'.
            max_concurrent (int): максимальное количество одновременных проверок.

        Возвращает:
            List[str]: список IP-адресов с открытым портом 9100.
        """
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError as e:
            self.logger.error(f"Неверный формат сети: {e}")
            return []

        my_ip = self.get_my_ip()
        hosts = [str(ip) for ip in network.hosts() if str(ip) != my_ip]

        self.logger.info(f"Запуск сканирования сети {network} (всего хостов: {len(hosts)})")
        print(f"Сканирование сети {network}...")

        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = [self._check_port(host, semaphore) for host in hosts]
        results = await asyncio.gather(*tasks)

        printers = [host for host, is_printer in zip(hosts, results) if is_printer]
        self.logger.info(f"Сканирование завершено. Найдено принтеров: {len(printers)}")
        return printers


class ExploitManager:
    """
    Менеджер для удобного управления функциями эксплуатации принтеров.
    Выступает фасадом к классам DeviceInfoGatherer и DisplayMessageSender.
    """

    def __init__(self):
        """Инициализация менеджера: создаёт экземпляры сборщика информации и отправителя сообщений."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.info_gatherer = DeviceInfoGatherer()
        self.display_sender = DisplayMessageSender()

    async def get_device_info(self, ip: str) -> Dict[str, Any]:
        """Получает полную информацию об устройстве через PJL (ID, CONFIG, STATUS, VARIABLES)."""
        self.logger.info(f"Запрос информации об устройстве {ip}")
        return await self.info_gatherer.gather_all(ip)

    async def get_device_id(self, ip: str) -> Optional[str]:
        """Быстрое получение только ID устройства."""
        self.logger.debug(f"Быстрое получение ID для {ip}")
        return await self.info_gatherer.get_device_id(ip)

    async def gather_multiple_devices(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Параллельно собирает информацию с нескольких принтеров.

        Параметры:
            ips (List[str]): список IP-адресов.

        Возвращает:
            List[Dict[str, Any]]: список результатов для каждого IP.
        """
        self.logger.info(f"Сбор информации с {len(ips)} устройств")
        tasks = [self.get_device_info(ip) for ip in ips]
        return await asyncio.gather(*tasks)

    async def send_rdymsg(self, ip: str, message: str) -> Dict[str, Any]:
        """Отправляет RDYMSG на принтер (сообщение готовности)."""
        return await self.display_sender.send_rdymsg(ip, message)

    async def send_opmsg(self, ip: str, message: str) -> Dict[str, Any]:
        """Отправляет OPMSG на принтер (переводит в офлайн)."""
        return await self.display_sender.send_opmsg(ip, message)

    async def clear_display(self, ip: str) -> Dict[str, Any]:
        """Очищает дисплей принтера, восстанавливая оригинальное сообщение."""
        return await self.display_sender.clear_display(ip)

    async def set_original_display_message(self, ip: str, message: str) -> None:
        """Сохраняет оригинальное сообщение для последующего восстановления."""
        await self.display_sender.set_original_message(ip, message)

    def print_device_info(self, info: Dict[str, Any]) -> None:
        """
        Красивый вывод информации об устройстве в консоль.

        Параметры:
            info (Dict[str, Any]): результат, возвращённый DeviceInfoGatherer.gather_all().
        """
        if not info.get('success'):
            print(f"\n[!] {info.get('ip')}: {info.get('error', 'Ошибка')}")
            return

        print(f"\n{'='*50}")
        print(f"📠 {info['ip']}")
        print(f"{'='*50}")

        device_info = info.get('info', {})

        if device_id := device_info.get('device_id'):
            print(f"ID: {device_id}")

        if config := device_info.get('config'):
            print("\n--- Конфигурация ---")
            if isinstance(config, dict):
                for key, value in config.items():
                    if key == 'items' and isinstance(value, list):
                        print(f"  {key}:")
                        for item in value:
                            print(f"    - {item}")
                    else:
                        print(f"  {key}: {value}")

        if status := device_info.get('status'):
            print(f"\nСтатус: {status}")

        if variables := device_info.get('variables'):
            print("\n--- Переменные ---")
            # Выделяем наиболее интересные ключи
            important_keys = ['MODEL', 'SERIALNUMBER', 'FIRMWAREDATE', 'PAGECOUNT']
            for key in important_keys:
                if key in variables:
                    print(f"  {key}: {variables[key]}")
            # Остальные переменные выводим в отдельной секции
            other = {k: v for k, v in variables.items() if k not in important_keys}
            if other:
                print("\n  Другое:")
                for key, value in other.items():
                    print(f"    {key}: {value}")

        print(f"{'='*50}")


class PrinterToolkit:
    """
    Высокоуровневый класс, объединяющий возможности сканирования сети и эксплуатации принтеров.
    Предоставляет простые методы для типовых сценариев использования.
    """

    def __init__(self):
        """Инициализация: создаёт сканер и менеджер эксплойтов."""
        self.scanner = NetworkScanner()
        self.exploit_manager = ExploitManager()
        self.logger = logging.getLogger(self.__class__.__name__)

    async def discover(self, cidr: str = "/24") -> List[str]:
        """
        Обнаруживает все принтеры в текущей подсети.

        Параметры:
            cidr (str): маска подсети (по умолчанию '/24').

        Возвращает:
            List[str]: список IP-адресов принтеров.
        """
        my_ip = self.scanner.get_my_ip()
        self.logger.info(f"Запуск обнаружения принтеров, мой IP: {my_ip}")
        print(f"Ваш IP: {my_ip}")

        printers = await self.scanner.scan(cidr=cidr)

        if printers:
            print(f"\n✅ Найдено принтеров: {len(printers)}")
            for ip in printers:
                print(f"  → {ip}")
        else:
            print("\n❌ Принтеров не найдено.")

        self.logger.info(f"Обнаружение завершено, найдено {len(printers)} устройств")
        return printers

    async def discover_custom_network(self, network_cidr: str) -> List[str]:
        """
        Обнаруживает принтеры в указанной сети.

        Параметры:
            network_cidr (str): сеть в формате CIDR (например, '192.168.1.0/24').

        Возвращает:
            List[str]: список IP-адресов принтеров.
        """
        self.logger.info(f"Обнаружение в указанной сети: {network_cidr}")
        print(f"Сканирование указанной сети: {network_cidr}")

        printers = await self.scanner.scan_custom_range(network_cidr)

        if printers:
            print(f"\n✅ Найдено принтеров: {len(printers)}")
            for ip in printers:
                print(f"  → {ip}")
        else:
            print("\n❌ Принтеров не найдено.")

        self.logger.info(f"Обнаружение в сети {network_cidr} завершено, найдено {len(printers)} устройств")
        return printers

    async def get_printer_info(self, ip: str) -> Dict[str, Any]:
        """
        Собирает и выводит подробную информацию об одном принтере.

        Параметры:
            ip (str): IP-адрес.

        Возвращает:
            Dict[str, Any]: результат сбора информации.
        """
        self.logger.info(f"Сбор детальной информации с {ip}")
        print(f"\n📊 Сбор информации с {ip}...")
        info = await self.exploit_manager.get_device_info(ip)
        self.exploit_manager.print_device_info(info)
        return info

    async def discover_and_gather(self, cidr: str = "/24") -> List[Dict[str, Any]]:
        """
        Комбинированный метод: сканирует подсеть, находит принтеры и собирает информацию с каждого.

        Параметры:
            cidr (str): маска подсети.

        Возвращает:
            List[Dict[str, Any]]: список результатов сбора информации.
        """
        printers = await self.discover(cidr)
        if not printers:
            return []

        self.logger.info(f"Сбор информации с {len(printers)} найденных принтеров")
        print(f"\n📊 Сбор информации с {len(printers)} устройств...")
        results = await self.exploit_manager.gather_multiple_devices(printers)

        for info in results:
            self.exploit_manager.print_device_info(info)

        self.logger.info("Сбор информации со всех устройств завершён")
        return results

    async def quick_device_id(self, ip: str) -> Optional[str]:
        """Быстрое получение ID устройства."""
        self.logger.debug(f"Быстрое получение ID устройства {ip}")
        return await self.exploit_manager.get_device_id(ip)

    async def send_printer_message(self, ip: str, message: str, take_offline: bool = False) -> Dict[str, Any]:
        """
        Отправляет сообщение на дисплей принтера.

        Параметры:
            ip (str): IP-адрес.
            message (str): текст сообщения.
            take_offline (bool): если True, используется OPMSG (принтер уходит в офлайн),
                                 иначе RDYMSG (принтер остаётся готовым).

        Возвращает:
            Dict[str, Any]: результат операции.
        """
        if take_offline:
            return await self.exploit_manager.send_opmsg(ip, message)
        else:
            return await self.exploit_manager.send_rdymsg(ip, message)

    async def clear_printer_message(self, ip: str) -> Dict[str, Any]:
        """Очищает сообщение на дисплее принтера, восстанавливая исходное состояние."""
        return await self.exploit_manager.clear_display(ip)

    async def save_original_display_message(self, ip: str, message: str) -> None:
        """Сохраняет оригинальное сообщение для последующего восстановления."""
        await self.exploit_manager.set_original_display_message(ip, message)


async def main():
    """
    Асинхронная точка входа в программу.
    Настраивает логирование в файл и демонстрирует примеры использования PrinterToolkit.
    """
    # Настройка логирования: все события пишутся в файл 'printer_toolkit.log' с кодировкой UTF-8.
    log_filename = "printer_toolkit.log"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8')
        ]
    )

    toolkit = PrinterToolkit()

    # --- Примеры использования (раскомментируйте нужные строки) ---

    # 1. Только найти принтеры в текущей сети /24
    # printers = await toolkit.discover()

    # 2. Найти принтеры в указанной сети
    # printers = await toolkit.discover_custom_network("192.168.1.0/24")

    # 3. Собрать информацию с конкретного принтера
    await toolkit.get_printer_info("192.168.8.20")

    # 4. Найти все принтеры и собрать информацию с каждого (основной сценарий разведки)
    # results = await toolkit.discover_and_gather()

    # 5. Быстро получить ID устройства
    # device_id = await toolkit.quick_device_id("192.168.1.50")
    # if device_id:
    #     print(f"Device ID: {device_id}")

    # 6. Отправить сообщение на экран принтера (RDYMSG)
    # await toolkit.send_printer_message("192.168.8.20", "Hello Printer!")

    # 7. Отправить сообщение с переводом в офлайн (OPMSG)
    # await toolkit.send_printer_message("192.168.8.20", "Offline Msg", take_offline=True)

    # 8. Очистить сообщение с экрана (восстановит "READY" или сохранённое)
    # await toolkit.clear_printer_message("192.168.8.20")

    # 9. Сохранить оригинальное сообщение вручную (если известно)
    # await toolkit.save_original_display_message("192.168.8.20", "CUSTOM")


if __name__ == "__main__":
    asyncio.run(main())