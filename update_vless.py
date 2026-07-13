import socket
import ssl
import time
import urllib.request
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

SOURCE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
OUTPUT_FILE = "fast_vless.txt"
LIMIT = 40
TIMEOUT = 3.0  # Время ожидания ответа сервера в секундах

def verify_vless_reality(link):
    """
    Глубокая проверка VLESS прокси. 
    Имитирует TLS-рукопожатие с проверкой SNI (сервера маскировки).
    """
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
        
        # Извлекаем параметры Reality (SNI / Server Name)
        query_params = parse_qs(parsed.query)
        sni = query_params.get('sni', [host])[0]  # Если sni нет, берем сам хост
        security = query_params.get('security', [''])[0]

        start_time = time.time()
        
        # 1. Проверяем базовое TCP соединение
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        
        # 2. Если прокси использует шифрование (reality или tls) — делаем честный TLS-Handshake
        if security in ['reality', 'tls']:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Настраиваем шифры, похожие на современные браузеры, чтобы обмануть ТСПУ
            context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
            
            secure_sock = context.wrap_socket(sock, server_hostname=sni)
            
            # Имитируем отправку HTTP-запроса к сайту маскировки через установленный TLS туннель
            http_request = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            secure_sock.sendall(http_request.encode('utf-8'))
            
            # Читаем ответ. Живой сервер маскировки Reality ОБЯЗАН ответить
            response = secure_sock.recv(512).decode('utf-8', errors='ignore')
            secure_sock.close()
            
            if not response or "HTTP/" not in response:
                return None  # Сервер сбросил соединение на этапе TLS (блокировка)
        else:
            # Если это простой VLESS без TLS (например, через WS)
            sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
            response = sock.recv(512).decode('utf-8', errors='ignore')
            sock.close()
            if "HTTP/" not in response:
                return None

        ping = (time.time() - start_time) * 1000
        return ping

    except Exception:
        return None

def worker(link):
    """Функция-помощник для многопоточного перебора"""
    ping = verify_vless_reality(link)
    if ping is not None:
        return link, ping
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

    print(f"Найдено {len(configs_to_test)} потенциальных VLESS ссылок. Начинаем глубокий тест...")

    valid_configs = []
    
    # Запускаем параллельную проверку в 20 потоков, чтобы гитхаб выполнял задачу быстро
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(worker, configs_to_test)
        for res in results:
            if res:
                link, ping = res
                valid_configs.append((link, ping))
                print(f" ПРОВЕРЕН: {urlparse(link).netloc.split('@')[-1]} -> {ping:.1f} мс")

    # Сортируем строго по реальному пингу от меньшего к большему
    valid_configs.sort(key=lambda x: x[1])
    top_configs = valid_configs[:LIMIT]

    # Записываем чистый результат
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config, _ in top_configs:
            f.write(config + "\n")
            
    print(f"\nТестирование завершено. Сохранено топ-{len(top_configs)} рабочих конфигураций.")

if __name__ == "__main__":
    main()
