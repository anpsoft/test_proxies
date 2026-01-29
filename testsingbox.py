import json
import subprocess
import time
import requests
import os
 
# Конфиг из предыдущего шага
config = {
    "log": {"level": "info"},
    "inbounds": [{
        "type": "mixed",
        "tag": "mixed-in",
        "listen": "127.0.0.1",
        "listen_port": 10808
    }],
    "outbounds": [{
        "type": "vless",
        "tag": "proxy",
        "server": "107.181.151.39",
        "server_port": 443,
        "uuid": "ed042cf7-efe0-49bd-848b-8d7e655111ff",
        "flow": "xtls-rprx-vision",
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": "www.mozilla.org",
            "reality": {
                "enabled": True,
                "public_key": "J-dv-HrWfQ_IOoyutv0Kg-rO8QwoRwc02dS1dS_tblk",
                "short_id": "1036b2383b72"
            },
            "utls": {
                "enabled": True,
                "fingerprint": "chrome"
            }
        }
    }],
    "route": {
        "rules": [{"protocol": "dns", "outbound": "direct"}],
        "final": "proxy"
    }
}
 
print("=== ТЕСТ ПРОКСИ ===")
 
# 1. Сохраняем конфиг
with open('test_config.json', 'w') as f:
    json.dump(config, f, indent=2)
print("✅ Конфиг сохранен")
 
# 2. Проверяем sing-box
singbox_exe = 'sing-box.exe'
if not os.path.exists(singbox_exe):
    print(f"❌ {singbox_exe} не найден!")
    exit()

# 3. Запускаем sing-box
print("🚀 Запускаем sing-box...")
process = None
 
try:
    process = subprocess.Popen(
        [singbox_exe, 'run', '-c', 'test_config.json'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    # Даем время на запуск
    time.sleep(4)
    
    # Проверяем, запустился ли
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        print(f"❌ Sing-box упал:")
        print(stderr)
        exit()
    
    print("✅ Sing-box запущен")
    print("🌐 Прокси: socks5://127.0.0.1:10808")
    
    # 4. Тестируем подключение
    print("\n=== ТЕСТ ПОДКЛЮЧЕНИЯ ===")
    
    test_urls = [
        "https://www.google.com",
        "https://1.1.1.1",
        "https://httpbin.org/ip"
    ]
    
    proxies = {
        'http': 'socks5://127.0.0.1:10808',
        'https': 'socks5://127.0.0.1:10808'
    }
    
    for url in test_urls:
        print(f"\nПробуем {url}...")
        try:
            start = time.time()
            response = requests.get(
                url,
                proxies=proxies,
                timeout=10,
                verify=False
            )
            elapsed = (time.time() - start) * 1000
            
            if response.status_code == 200:
                print(f"✅ Успех! {elapsed:.0f} мс")
                if url == "https://httpbin.org/ip":
                    print(f"   Ваш IP: {response.text}")
            else:
                print(f"⚠️  Код: {response.status_code}")
                
        except requests.exceptions.ConnectTimeout:
            print("❌ Таймаут подключения")
        except requests.exceptions.ConnectionError:
            print("❌ Ошибка соединения")
        except Exception as e:
            print(f"❌ Ошибка: {type(e).__name__}: {e}")
    
    # 5. Проверка через curl
    print("\n=== ПРОВЕРКА ЧЕРЕЗ CURL ===")
    try:
        result = subprocess.run(
            ['curl', '-x', 'socks5h://127.0.0.1:10808',
             '-s', '--connect-timeout', '10',
             'https://httpbin.org/ip'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"✅ Curl работает: {result.stdout}")
        else:
            print(f"❌ Curl ошибка: {result.stderr}")
    except FileNotFoundError:
        print("ℹ️  Curl не найден")
    
    print("\n✅ Тест завершен")
    print("Нажмите Enter для остановки...")
    input()
    
except KeyboardInterrupt:
    print("\n⏹️ Остановлено")
except Exception as e:
    print(f"\n❌ Ошибка: {e}")
    import traceback
    traceback.print_exc()
finally:
    # Останавливаем sing-box
    if process:
        print("\n🛑 Останавливаем sing-box...")
        process.terminate()
        try:
            process.wait(timeout=3)
        except:
            process.kill()
        print("✅ Остановлен")
    
    # Удаляем конфиг
    if os.path.exists('test_config.json'):
        os.remove('test_config.json')