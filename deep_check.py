#!/usr/bin/env python3
# simple_local_check.py - Упрощенная проверка с детальной отладкой
 
import json
import time
import requests
import subprocess
import tempfile
import os
import sys
import configparser
from datetime import datetime
from urllib.parse import urlparse, parse_qs
 
class SimpleLocalChecker:
    def __init__(self, config_file='option.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        
        # Путь к sing-box
        self.singbox_path = self.config.get('paths', 'singbox_path', fallback='').strip()
        if not self.singbox_path:
            self.singbox_path = 'sing-box.exe' if os.name == 'nt' else './sing-box'
        
        print(f"⚙️  Sing-box: {self.singbox_path}")
        
        if not os.path.exists(self.singbox_path):
            print(f"❌ Sing-box не найден: {self.singbox_path}")
            sys.exit(1)
        
        # Простой тестовый URL
        self.test_url = "https://httpbin.org/ip"
        self.test_timeout = 5
        
        # Для отладки
        self.debug = True
        
    def parse_vless(self, url, parsed):
        """Простой парсер VLESS"""
        try:
            query = parse_qs(parsed.query)
            
            config = {
                "type": "vless",
                "tag": "proxy",
                "server": parsed.hostname,
                "server_port": int(parsed.port) if parsed.port else 443,
                "uuid": parsed.username,
            }
            
            # Фильтр неподдерживаемых
            network = query.get('type', ['tcp'])[0]
            if network in ['xhttp', 'httpupgrade', 'vision', 'splithttp']:
                return None
            
            # TLS
            security = query.get('security', [''])[0]
            sni = query.get('sni', [''])[0] or parsed.hostname
            
            if security in ['tls', 'reality']:
                config["tls"] = {
                    "enabled": True,
                    "server_name": sni,
                    "insecure": query.get('allowInsecure', ['0'])[0] == '1',
                }
            
            # Transport
            if network == "ws":
                config["transport"] = {
                    "type": "ws",
                    "path": query.get('path', ['/'])[0],
                }
            
            return config
            
        except Exception as e:
            if self.debug:
                print(f"    🐛 Ошибка парсинга: {e}")
            return None
    
    def create_simple_config(self, proxy_config, local_port):
        """Минимальный конфиг для тестирования"""
        config = {
            "log": {
                "level": "info",  # Для отладки
                "output": "console"
            },
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": local_port,
                "sniff": False
            }],
            "outbounds": [
                proxy_config,
                {"type": "direct", "tag": "direct"}
            ],
            "route": {
                "rules": [
                    {"outbound": "proxy", "inbound": ["socks-in"]}
                ],
                "final": "proxy"
            }
        }
        return config
    
    def test_connection(self, local_port):
        """Простой тест соединения"""
        proxy_dict = {
            'http': f'socks5://127.0.0.1:{local_port}',
            'https': f'socks5://127.0.0.1:{local_port}'
        }
        
        try:
            # 1. Простой тест
            response = requests.get(
                self.test_url,
                proxies=proxy_dict,
                timeout=self.test_timeout,
                verify=False
            )
            
            if response.status_code == 200:
                ip_data = response.json()
                print(f"    ✅ Получен IP: {ip_data.get('ip')}")
                return True, ip_data.get('ip')
            else:
                print(f"    ❌ HTTP {response.status_code}")
                return False, None
                
        except requests.exceptions.ConnectTimeout:
            print("    ⏱️  Таймаут подключения")
            return False, None
        except requests.exceptions.ConnectionError as e:
            print(f"    🔌 Ошибка соединения: {str(e)[:50]}")
            return False, None
        except Exception as e:
            print(f"    ⚠️  Ошибка: {type(e).__name__}")
            return False, None
    
    def check_proxy(self, proxy_url, port):
        """Проверяем одну прокси"""
        print(f"\n🔍 [{port-16000+1}] {proxy_url[:60]}...")
        
        # Парсим
        parsed = urlparse(proxy_url)
        proxy_config = self.parse_vless(proxy_url, parsed)
        
        if not proxy_config:
            print("    ⚠️  Не удалось распарсить")
            return None
        
        # Создаем конфиг
        config = self.create_simple_config(proxy_config, port)
        
        # Сохраняем конфиг для отладки
        config_filename = f"debug_{port}.json"
        with open(config_filename, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        print(f"    📄 Конфиг: {config_filename}")
        
        # Запускаем sing-box
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        
        process = subprocess.Popen(
            [self.singbox_path, 'run', '-c', config_filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            text=True,
            encoding='utf-8',
            bufsize=1
        )
        
        # Ждем запуска и читаем логи
        print("    ⏳ Запускаю sing-box...")
        time.sleep(2)
        
        # Проверяем запустился ли
        if process.poll() is not None:
            stderr = process.stderr.read()
            print(f"    ❌ Sing-box упал: {stderr[:100]}")
            
            # Сохраняем логи
            with open(f"error_{port}.log", 'w') as f:
                f.write(stderr)
            
            process.terminate()
            return None
        
        print("    ✅ Sing-box запущен")
        
        # Тестируем соединение
        success, ip = self.test_connection(port)
        
        # Останавливаем процесс
        process.terminate()
        try:
            process.wait(timeout=2)
        except:
            process.kill()
        
        # Удаляем временные файлы
        try:
            os.unlink(config_filename)
        except:
            pass
        
        if success and ip:
            # Дополнительная проверка через ipapi.co
            try:
                geo_response = requests.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=3
                )
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    country = geo_data.get('country_name', 'Unknown')
                    isp = geo_data.get('org', '')[:30]
                    
                    print(f"    🌍 Страна: {country}")
                    print(f"    🏢 Провайдер: {isp}")
                    
                    # Сохраняем
                    timestamp = datetime.now().strftime("%m%d_%H%M")
                    filename = f"{country.replace(' ', '_')}_{ip.split('.')[-2]}_{timestamp}.txt"
                    
                    return {
                        'proxy': proxy_url,
                        'filename': filename,
                        'ip': ip,
                        'country': country,
                        'isp': isp
                    }
            except:
                print("    ⚠️  Не удалось получить гео")
        
        return None if not success else {
            'proxy': proxy_url,
            'filename': f"proxy_{ip}_{datetime.now().strftime('%m%d_%H%M')}.txt",
            'ip': ip,
            'country': 'Unknown',
            'isp': 'Unknown'
        }
    
    def run(self, input_file):
        """Запуск проверки"""
        print(f"\n📄 Читаю файл: {input_file}")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        print(f"📊 Всего прокси: {len(lines)}")
        print(f"🔧 Тестовый URL: {self.test_url}")
        print(f"⏱️  Таймаут: {self.test_timeout}с")
        print("-" * 60)
        
        successful = []
        port = 16000
        
        for i, proxy_url in enumerate(lines):
            print(f"\n[{i+1}/{len(lines)}] ", end="")
            
            result = self.check_proxy(proxy_url, port)
            port += 1
            
            if result:
                successful.append(result)
                
                # Сохраняем сразу
                os.makedirs('checked', exist_ok=True)
                filepath = os.path.join('checked', result['filename'])
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(f"# Проверено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# IP: {result['ip']}\n")
                    f.write(f"# Страна: {result['country']}\n")
                    f.write(f"# Провайдер: {result['isp']}\n\n")
                    f.write(result['proxy'] + "\n")
                
                print(f"    💾 Сохранено: {filepath}")
            
            # Пауза между проверками
            if i < len(lines) - 1:
                time.sleep(1)
        
        # Отчет
        print(f"\n{'='*60}")
        print("📊 ИТОГИ:")
        print(f"✅ Рабочих: {len(successful)}/{len(lines)}")
        
        if successful:
            print("\n🌍 Найденные прокси:")
            for proxy in successful:
                print(f"  • {proxy['country']}: {proxy['ip']} ({proxy['isp'][:20]})")
            
            # Создаем общий файл
            summary_file = f"working_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(f"# Рабочие прокси ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                f.write(f"# Найдено: {len(successful)} из {len(lines)}\n\n")
                for proxy in successful:
                    f.write(f"# {proxy['country']} - {proxy['isp'][:30]}\n")
                    f.write(proxy['proxy'] + "\n\n")
            
            print(f"\n📋 Сводный файл: {summary_file}")
        
        return successful

def main():
    print("🔧 ПРОСТАЯ ЛОКАЛЬНАЯ ПРОВЕРКА ПРОКСИ")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("Использование: python simple_local_check.py <файл_с_прокси>")
        print("Пример: python simple_local_check.py proxies.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    checker = SimpleLocalChecker()
    checker.run(input_file)
    
    print("\n🎉 Готово!")

if __name__ == '__main__':
    main()