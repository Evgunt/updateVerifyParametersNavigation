import socket
import ssl
import time
import urllib.request
from urllib.parse import urlparse
# updateVerifyParametersNavigation
SOURCE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
OUTPUT_FILE = "fast_vless.txt"
LIMIT = 40
TIMEOUT = 3.0  # Увеличиваем таймаут для полноценного HTTP-ответа

def check_http_access(host, port):
    """
    Проверяет реальный HTTP-доступ, отправляя валидный HTTP-запрос
    и ожидая код ответа (например, 200, 301, 400, 404)
    """
    start_time = time.time()
    try:
        # Создаем TCP соединение
        sock = socket.create_connection((host, int(port)), timeout=TIMEOUT)

        # Оборачиваем в SSL, так как VLESS обычно работает поверх TLS (порт 443)
        context = ssl._create_unverified_context()
        secure_sock = context.wrap_socket(sock, server_hostname=host)

        # Отправляем простейший HTTP-запрос к серверу
        http_request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        secure_sock.sendall(http_request.encode('utf-8'))

        # Читаем первый кусочек ответа
        response = secure_sock.recv(1024).decode('utf-8', errors='ignore')
        secure_sock.close()

        # Если сервер ответил валидным HTTP-статусом, значит веб-сервер активен
        if "HTTP/" in response:
            # Извлекаем код ответа (например, 200, 404, 400)
            status_line = response.split('\r\n')[0]
            ping = (time.time() - start_time) * 1000
            return ping, status_line

        return float('inf'), None
    except Exception:
        return float('inf'), None


def parse_vless(link):
    try:
        parsed = urlparse(link.strip())
        if parsed.scheme != 'vless':
            return None
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.split('@')[-1]
        if ':' in netloc:
            host, port = netloc.split(':')
            return host, int(port)
    except Exception:
        pass
    return None


def main():
    print("Скачивание списка...")
    try:
        req = urllib.request.Request(SOURCE_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            lines = response.read().decode('utf-8').splitlines()
    except Exception as e:
        print(f"Ошибка скачивания: {e}")
        return

    tested_configs = []

    for line in lines:
        link = line.strip()
        if not link or link.startswith('#') or not link.startswith('vless://'):
            continue

        parsed_data = parse_vless(link)
        if parsed_data:
            host, port = parsed_data
            ping, status = check_http_access(host, port)

            if ping != float('inf'):
                tested_configs.append((link, ping))
                print(f"Доступен: {host}:{port} -> {ping:.1f} мс (Статус: {status})")
            else:
                print(f"Нет HTTP ответа: {host}:{port}")

    tested_configs.sort(key=lambda x: x[1])
    top_configs = tested_configs[:LIMIT]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config, _ in top_configs:
            f.write(config + "\n")

    print(f"\nОбновлено! Сохранено конфигураций: {len(top_configs)}")


if __name__ == "__main__":
    main()