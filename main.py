import asyncio
import socket 
import ipaddress
import platform
from typing import List, Optional


def recognise_network() -> str:
    """Возвращает адрес устройства в сети"""
    return socket.gethostbyname(socket.gethostname())


async def check_printer_ports(ip: str, semaphore: asyncio.Semaphore) -> bool:
    """
    Проверка специфичных портов принтеров
    """
    async with semaphore:
        # Только порты, характерные для принтеров
        printer_ports = [9100, 515, 631]
        
        for port in printer_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=0.2
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                continue
        return False


async def ping_host(ip: str, ping_semaphore: asyncio.Semaphore, port_semaphore: asyncio.Semaphore) -> Optional[dict]:
    """
    Асинхронный пинг хоста + проверка портов принтера
    """
    async with ping_semaphore:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '300', ip]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(process.communicate(), timeout=0.5)
            
            if process.returncode == 0:
                # Проверяем порты принтера
                is_printer = await check_printer_ports(ip, port_semaphore)
                
                # Получаем имя хоста для информации
                loop = asyncio.get_event_loop()
                try:
                    hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                    hostname_str = hostname[0]
                except:
                    hostname_str = "Неизвестно"
                
                return {
                    'ip': ip,
                    'hostname': hostname_str,
                    'is_printer': is_printer
                }
            return None
        except:
            return None


async def scan_network(local_ip: str, max_concurrent: int = 200) -> List[dict]:
    """Асинхронное сканирование сети с поиском принтеров"""
    network = ipaddress.ip_network(
        '.'.join(local_ip.split('.')[:-1]) + '.0/24', 
        strict=False
    )
    hosts = [str(ip) for ip in network.hosts()]
    
    ping_semaphore = asyncio.Semaphore(max_concurrent)
    port_semaphore = asyncio.Semaphore(50)
    
    tasks = [ping_host(host, ping_semaphore, port_semaphore) for host in hosts]
    results = await asyncio.gather(*tasks)
    
    return [result for result in results if result is not None]


def print_results(active_hosts: List[dict]) -> None:
    """Вывод результатов"""
    if not active_hosts:
        print("\n Активных хостов не найдено!")
        return
    
    printers = [host for host in active_hosts if host['is_printer']]
    
    if printers:
        print(f"\nНАЙДЕННЫЕ ПРИНТЕРЫ ({len(printers)}):")
        print(" " + "-" * 40)
        for printer in printers:
            print(f"| {printer['ip']:15} | {printer['hostname']:20}|")
        print(" " + "-" * 40)
    else:
        print("\nПринтеров не найдено")
    

def main():
    local_ip = recognise_network()
    print(f"Ваш локальный IP: {local_ip}")
    print(f"Сеть: {'.'.join(local_ip.split('.')[:-1]) + '.0/24'}")
    
    active_hosts = asyncio.run(scan_network(local_ip))
    print_results(active_hosts)


if __name__ == "__main__":
    main()
