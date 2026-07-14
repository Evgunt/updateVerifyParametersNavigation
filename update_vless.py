import socket
import ssl
import time
import urllib.request
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# НАСТРОЙКИ: Теперь здесь список (массив) ваших источников
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
]

# Ссылка, для которой нужно помечать конфигурации префиксом "WL" в названии
WL_SOURCE_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

OUTPUT_FILE = "fast_vless.txt"
LIMIT = 40
TIMEOUT = 3.0  # Ожидание ответа в секундах

def get_country_code(host):
    """Определяет код страны для IP-адреса или домена"""
    try:
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
    """Глубокая TLS-проверка с фильтрацией по ГЕО (исключая RU, UA и вхождения Russia)"""
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
        
        # Шаг 1: Гео-фильтрация по IP
        country = get_country_code(host)
        if country in ['RU', 'UA']:
            print(f" ИГНОР: {host} физически в {country}")
            return None
        
        # Извлекаем параметры Reality
        query_params = parse_qs(parsed.query)
        sni = query_params.get('sni', [host])
        security = query_params.get('security', [''])

        start_time = time.time()
        
        # Шаг 2: TCP Соединение
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        
        # Шаг 3: TLS-Handshake (Имитация браузера)
        if security in ['reality', 'tls']:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
            
            secure_sock = context.wrap_socket(sock, server_hostname=sni)
            
            # HTTP-запрос сайту маскировки
            http_request = f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            secure_sock.sendall(http_request.encode('utf-8'))
            
            response = secure_sock.recv(512).decode('utf-8', errors='ignore')
            secure_sock.close()
            
            if not response or "HTTP/" not in response:
                return None
        else:
            # Для базовых WS-конфигураций без TLS
            sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
            response = sock.recv(512).decode('utf-8', errors='ignore')
            sock.close()
            if "HTTP/" not in response:
                return None

        ping = (time.time() - start_time) * 1000
        return ping, country

    except Exception:
        return None

def worker(item):
    """Потоковый обработчик с жестким географическим и скоростным фильтром"""
    link, is_wl = item
    res = verify_vless_reality(link)
    if res is not None:
        ping, country = res
            
        # 2. Фильтр по пингу дата-центра: если даже на Гитхабе пинг до него больше 80мс, 
        # то на мобильном интернете в РФ он превратится в 200+ мс. Убираем его.
        if ping > 100.0:
            print(f" СКИП: Высокий базовый пинг на GitHub ({ping:.1f} мс)")
            return None
        
        # Если сервер идеален по гео и скорости, добавляем префикс WL (если нужно)
        if is_wl:
            parsed = urllib.parse.urlparse(link)
            new_fragment = f"WL-{parsed.fragment}" if parsed.fragment else "WL-Server"
            link = urllib.parse.urlunparse(parsed._replace(fragment=new_fragment))
            
        return link, ping, country
    return None

def main():
    configs_to_test = []
    
    # Цикл по всем указанным источникам
    for url in SOURCES:
        print(f"Скачивание списка из источника: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                lines = response.read().decode('utf-8').splitlines()
        except Exception as e:
            print(f"Ошибка при скачивании {url}: {e}")
            continue

        is_wl = (url == WL_SOURCE_URL)

        for line in lines:
            link = line.strip()
            if not link.startswith('vless://'):
                continue
                
            # Проверка текста на вхождение слова "russia" (без учета регистра)
            if "russia" in link.lower():
                print(f" СКИП (Найдено 'Russia' в тексте ссылки): {link[:40]}...")
                continue
                
            configs_to_test.append((link, is_wl))

    print(f"\nСбор завершен. Всего ссылок для проверки: {len(configs_to_test)}. Начинаем многопоточный тест...")

    valid_configs = []
    
    # 15 параллельных потоков для предотвращения бана от GeoIP API
    with ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(worker, configs_to_test)
        for res in results:
            if res:
                link, ping, country = res
                valid_configs.append((link, ping))
                print(f" ОК [{country}]: {urllib.parse.urlparse(link).fragment or 'Без имени'} -> {ping:.1f} мс")

    # Сортировка по пингу
    valid_configs.sort(key=lambda x: x)
    top_configs = valid_configs[:LIMIT]

    # Сохранение результатов
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config, _ in top_configs:
            f.write(config + "\n")
            
    print(f"\nГотово! Отфильтровано. Топ-{len(top_configs)} рабочих конфигураций записаны в {OUTPUT_FILE}.")

if __name__ == "__main__":
    main()
