import socket
import ssl
import urllib.request
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# НАСТРОЙКИ: Ссылки на файлы с конфигурациями
SOURCES = [
    "https://githubusercontent.com",
    "https://githubusercontent.com"
]

OUTPUT_FILE = "fast_vless.txt"
TIMEOUT = 3.0  # Ожидание ответа сервера в секундах

def check_server(link):
    """Улучшенная проверка: TCP -> TLS -> отправка HTTP-запроса"""
    try:
        parsed = urlparse(link.strip())
        if parsed.scheme != 'vless':
            return None
        
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.split('@')[-1]
        host, port = netloc.split(':')
        port = int(port)
        
        # 1. Защищенное TCP соединение
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        
        # 2. TLS-Handshake
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        secure_sock = context.wrap_socket(sock, server_hostname=host)
        
        # 3. Отправляем легкий запрос, чтобы убедиться, что сервер пропускает трафик
        # (Имитируем базовый запрос к сайту маскировки)
        http_request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        secure_sock.sendall(http_request.encode('utf-8'))
        
        # Читаем первые байты ответа. Если сервер «живой» — он что-то ответит
        response = secure_sock.recv(16)
        
        secure_sock.close()
        
        if response:
            return link
        return None
    except Exception:
        return None

def main():
    configs_to_test = set()  # Автоматическое исключение дубликатов
    
    # Скачивание конфигураций из всех источников
    for url in SOURCES:
        print(f"Скачивание: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5.0) as response:
                for line in response.read().decode('utf-8').splitlines():
                    link = line.strip()
                    
                    if not link.startswith('vless://'):
                        continue
                        
                    # Текстовый фильтр на вхождение слова "russia"
                    if "russia" in link.lower():
                        print(f" СКИП (Найдено 'Russia' в ссылке): {link[:50]}...")
                        continue
                        
                    configs_to_test.add(link)
        except Exception as e:
            print(f"Ошибка скачивания источника {url}: {e}")

    print(f"\nСобрано уникальных ссылок для теста: {len(configs_to_test)}. Проверка работоспособности...")

    valid_configs = []
    
    # Многопоточная проверка
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_server, configs_to_test)
        for res in results:
            if res:
                valid_configs.append(res)
                print(f" Рабочий: {urlparse(res).fragment or 'Без имени'}")

    # Сохранение результатов в файл
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config in valid_configs:
            f.write(config + "\n")
            
    print(f"\nПроверка завершена. Рабочие конфигурации ({len(valid_configs)} шт.) записаны в {OUTPUT_FILE}.")

if __name__ == "__main__":
    main()
