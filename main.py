import asyncio
import socket
import ipaddress
from typing import List, Optional


class NetworkScanner:
    """Сканер сети с поддержкой быстрого (только IP) и детального (с именами) режимов."""

    def __init__(self, printer_ports: Optional[List[int]] = None):
        self.printer_ports = printer_ports if printer_ports is not None else [9100, 515, 631]
        self._hostname_cache = {}

    def recognise_network(self) -> str:
        return socket.gethostbyname(socket.gethostname())

    # ---------- Быстрый режим (без имён) ----------
    async def _check_port_fast(self, ip: str, semaphore: asyncio.Semaphore, port: int) -> bool:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=0.05
                )
                writer.close()
                await writer.wait_closed()
                return True
            except Exception:
                return False

    async def _check_printer_fast(self, ip: str, port_semaphore: asyncio.Semaphore) -> Optional[str]:
        for port in self.printer_ports:
            if await self._check_port_fast(ip, port_semaphore, port):
                return ip
        return None

    async def fast_scan(self, local_ip: str, max_concurrent: int = 200) -> List[str]:
        """Быстрое сканирование: возвращает IP-адреса принтеров (без имён)."""

        network = ipaddress.ip_network('.'.join(local_ip.split('.')[:-1]) + '.0/24', strict=False)
        hosts = [str(ip) for ip in network.hosts() if str(ip) != local_ip]

        port_semaphore = asyncio.Semaphore(max_concurrent)

        tasks = [self._check_printer_fast(host, port_semaphore) for host in hosts]
        results = await asyncio.gather(*tasks)

        return [ip for ip in results if ip is not None]

    # ---------- Детальный режим (с именами) ----------
    async def _check_printer_ports(self, ip: str, semaphore: asyncio.Semaphore) -> bool:
        async with semaphore:
            for port in self.printer_ports:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=0.2
                    )
                    writer.close()
                    await writer.wait_closed()
                    return True
                except Exception:
                    continue
            return False

    async def _get_hostname_async(self, ip: str) -> str:
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        
        loop = asyncio.get_running_loop()

        try:
            hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            result = hostname[0]
        except Exception:
            result = "Неизвестно"

        self._hostname_cache[ip] = result
        return result

    async def full_scan(self, local_ip: str, max_concurrent: int = 200) -> List[dict]:
        """Детальное сканирование: возвращает IP и имена хостов принтеров."""
        network = ipaddress.ip_network('.'.join(local_ip.split('.')[:-1]) + '.0/24', strict=False)

        hosts = [str(ip) for ip in network.hosts() if str(ip) != local_ip]
        port_semaphore = asyncio.Semaphore(50)

        async def check_full(ip: str):
            if await self._check_printer_ports(ip, port_semaphore):
                hostname = await self._get_hostname_async(ip)
                return {'ip': ip, 'hostname': hostname, 'is_printer': True}
            return None

        tasks = [check_full(ip) for ip in hosts]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r is not None]

    @staticmethod
    def print_results(printers: List[dict]) -> None:
        if not printers:
            print("\nПринтеров не найдено!")
            return
        print(f"\nНайдено принтеров: {len(printers)}")
        print(" " + "-" * 40)
        for printer in printers:
            print(f"| {printer['ip']:15} | {printer['hostname']:20}|")
        print(" " + "-" * 40)


class ExploitManager:
    """Заглушка для будущих эксплойтов."""
    pass


class PrinterToolkit:
    """Аккумулирующий класс для сканирования и эксплуатации принтеров."""

    def __init__(self, printer_ports: Optional[List[int]] = None):
        self.scanner = NetworkScanner(printer_ports)
        self.exploit_manager = ExploitManager()

    def scan_quick(self):
        """Быстрое сканирование (только IP-адреса)."""

        local_ip = self.scanner.recognise_network()
        
        print(f"Ваш локальный IP: {local_ip}")
        print(f"Быстрое сканирование сети {'.'.join(local_ip.split('.')[:-1]) + '.0/24'}...")
        
        printers = asyncio.run(self.scanner.fast_scan(local_ip))
        
        if printers:
            print("\nНайдены принтеры (IP):")
            for ip in printers:
                print(f"  {ip}")
        else:
            print("\nПринтеров не найдено.")

    def scan_detailed(self):
        """Детальное сканирование (с именами хостов)."""
        local_ip = self.scanner.recognise_network()
        print(f"Ваш локальный IP: {local_ip}")
        print(f"Детальное сканирование сети {'.'.join(local_ip.split('.')[:-1]) + '.0/24'}...")
        printers = asyncio.run(self.scanner.full_scan(local_ip))
        self.scanner.print_results(printers)


def main():
    toolkit = PrinterToolkit()
    toolkit.scan_quick()      # быстро, только IP
    toolkit.scan_detailed()  # подробно, с именами


if __name__ == "__main__":
    main()