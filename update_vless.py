import socket
import ssl
import time
import urllib.request
import re
import subprocess
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import sys

# ==================== НАСТРОЙКИ СКРИПТА ====================
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
]

OUTPUT_FILE = "fast_vless.txt"
LIMIT = 60    # Максимальное количество рабочих ссылок для сохранения
TIMEOUT = 3.0  # Ожидание ответа сервера в секундах

# ==================== НАСТРОЙКИ GIT ====================
GIT_BRANCH = "main"  
COMMIT_MESSAGE = "Auto-update: 60 fast VLESS configs"

# Скрипт автоматически определяет папку, в которой он лежит на компьютере
REPO_PATH = os.path.dirname(os.path.abspath(__file__))

def run_git_command(args):
    """Безопасный запуск команд Git с логированием ошибок"""
    try:
        result = subprocess.run(
            args, 
            cwd=REPO_PATH, 
            capture_output=True, 
            text=True, 
            check=True, 
            encoding='utf-8'
        )
        print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print(f"Ошибка Git при выполнении {' '.join(args)}:")
        print(f"Код возврата: {e.returncode}")
        print(f"Ошибка: {e.stderr.strip()}")
        return False

def push_to_git():
    """Процесс синхронизации с GitHub"""
    print("\n--- Запуск синхронизации с Git ---")
    
    # 1. Добавляем файл в индекс
    if not run_git_command(["git", "add", OUTPUT_FILE]):
        return
        
    # Проверяем, есть ли изменения, чтобы не плодить пустые коммиты
    try:
        status = subprocess.run(["git", "status", "--porcelain"], cwd=REPO_PATH, capture_output=True, text=True, check=True)
        if not status.stdout.strip():
            print("Изменений в файле нет, Git push отменен.")
            return
    except Exception:
        pass

    # 2. Создаем коммит
    if not run_git_command(["git", "commit", "-m", COMMIT_MESSAGE]):
        return
        
    # 3. Отправляем в репозиторий
    if run_git_command(["git", "push", "origin", GIT_BRANCH]):
        print("Данные успешно отправлены в репозиторий GitHub!")
    else:
        print("Не удалось отправить данные в GitHub.")

def check_server(link):
    """Проверка VLESS REALITY (type=raw): TCP + TLS Handshake с замером пинга"""
    try:
        link_clean = link.strip()
        if not link_clean.startswith('vless://'):
            return None
        
        match = re.search(r'@([^:/?#]+):(\d+)', link_clean)
        if not match:
            return None
            
        host = match.group(1)
        port = int(match.group(2))
        
        sni_match = re.search(r'[?&]sni=([^&#]+)', link_clean)
        sni = sni_match.group(1) if sni_match else host
        
        start_time = time.perf_counter()
        
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        secure_sock = context.wrap_socket(sock, server_hostname=sni)
        secure_sock.do_handshake() 
        secure_sock.close()
        
        elapsed_time = time.perf_counter() - start_time
        return (link_clean, elapsed_time)
    except Exception:
        return None

def main():
    # Меняем текущую рабочую директорию на папку репозитория
    if os.path.exists(REPO_PATH):
        os.chdir(REPO_PATH)
    else:
        print(f"Критическая ошибка: Путь {REPO_PATH} не найден!")
        return

    configs_to_test = set()
    
    for url in SOURCES:
        print(f"Скачивание: {url}")
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5.0) as response:
                for line in response.read().decode('utf-8').splitlines():
                    link = line.strip()
                    
                    if not link or link.startswith('#'):
                        continue
                    if not link.startswith('vless://'):
                        continue
                        
                    link_lower = link.lower()
                    if "russia" in link_lower or "united states" in link_lower or "ukraine" in link_lower:
                        continue
                        
                    configs_to_test.add(link)
        except Exception as e:
            print(f"Ошибка скачивания источника {url}: {e}")

    print(f"\nСобрано уникальных ссылок: {len(configs_to_test)}. Тестирование...")

    valid_configs = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(check_server, configs_to_test)
        for res in results:
            if res:
                valid_configs.append(res)

    # Сортировка по пингу
    valid_configs.sort(key=lambda x: x[1])
    top_configs = valid_configs[:LIMIT]

    # Сохранение результатов
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for config, ping in top_configs:
            f.write(config + "\n")
            
    print(f"\nВыборка завершена. Топ-{len(top_configs)} конфигураций записаны.")
    
    # Запуск авто-пуша в Git
    push_to_git()

if __name__ == "__main__":
    main()
