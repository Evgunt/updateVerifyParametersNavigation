import socket
import ssl
import time
import urllib.request
import json
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

SOURCE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
OUTPUT_FILE = "fast_vless.txt"
LIMIT = 40
TIMEOUT = 3.0  # Ожидание ответа в секундах

def get_country_code(host):
    """Определяет код страны для IP-адреса или домена"""
    try:
        # Если в ссылке домен, преобразуем его в IP для корректного гео-запроса
        ip = socket.gethostbyname(host)
        geo_url = f"http://ip-api.com{ip}?fields=status,countryCode"
        
        req = urllib.request.Request(geo_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.0) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get("status") == "success":
                return data.get("countryCode")
    except Exception:
        pass
    return "UNKNOWN"

def verify_vless_reality(link):
    """Глубокая TLS-проверка с фильтрацией по ГЕО (исключая RU и UA)"""
    try:
        parsed = urlparse(link.strip())
        if parsed.scheme != 'vless':
            return None
        
        # Извлекаем хост и порт
        netloc = parsed.netloc
        if '@' in netloc:
            netloc = netloc.split('@')[-1]
        host, port = netloc.split(':')
        port = int(port)
        
        # Шаг 1: Гео-фильтрация (Проверяем страну перед отправкой тяжелых пакетов)
        country = get_country_code(host)
        if country in ['RU', 'UA']:
            print(f" ИГНОР: {host} находится в {country} (Пропуск)")
            return None
        
        # Извлекаем параметры Reality
        query_params = parse_qs(parsed.query)
        sni = query_params.get('sni', [host])[0]
        security = query_params.get('security', [''])[0]

        start_time = time.time()
        
        # Шаг 2: TCP Соединение
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        
        # Шаг 3: TLS-Handshake (Имитация браузера для пробития ТСПУ)
        if security in ['reality', 'tls']:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
            
            secure_sock = context.wrap_socket(sock, server_hostname=sni)
            
            # Отправляем HTTP-запрос сайту маскировки внутри туннеля
            http_request = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            secure_sock.sendall(http_request.encode('utf-8'))
            
            response = secure_sock.recv(512).decode('utf-8', errors='ignore')
            secure_sock.close()
            
            if not response or "HTTP/" not in response:
                return None
        else:
            # Для базовых WS-конфигураций без шифрования
            sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
            response = sock.recv(512).decode('utf-8', errors='ignore')
            sock.close()
            if "HTTP/" not in response:
                return None

        ping = (time.time() - start_time) * 1000
        return ping, country

    except Exception:
        return None

def worker(link):
    """Потоковый обработчик"""
    res = verify_vless_reality(link)
    if res is not None:
        ping, country = res
        return link, ping, country
    return None

def main():
    print("Скачивание списка конфигураций...")
    try:
        req = urllib.request.Request(SOURCE_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            lines = response.read().decode('utf-8').splitlines()
    except Exception as e:
        print(f"Ошибка при скачивании исходного файла: {e}")
        return

    configs_to_test = []
    for line in lines:
        link = line.strip()
        if link.startswith('vless://'):
            configs_to_test.append(link)

    print(f"Найдено {len(configs_to_test)} потенциальных VLESS ссылок. Начинаем многопоточный тест...")

    valid_configs = []
    
    # Ограничиваем до 15 потоков, чтобы GeoIP API не выдало бан за слишком частые запросы
    with ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(worker, configs_to_test)
        for res in results:
            if res:
                link, ping, country = res
                valid_configs.append((link, ping))
                print(f" ОК [{country}]: {urlparse(link).netloc.split('@')[-1]} -> {ping:.1f} мс")

    # Сортировка по реальному пингу (от быстрых к медленным)
    valid_configs.sort(key=lambda x: x[1])
    top_configs = valid_configs[:LIMIT]

    # Запись итогового списка топ-40 без RU и UA
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config, _ in top_configs:
            f.write(config + "\n")
            
    print(f"\nТестирование завершено. Исключены RU и UA. Сохранено топ-{len(top_configs)} рабочих конфигураций.")

if __name__ == "__main__":
    main()
