#!/usr/bin/env python3
# simple_tester.py - Детальный однопоточный тестер прокси
 
import os
import sys
import json
import time
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import urlparse, parse_qs
 
import requests
 
from core import Config, ProxyParser, SingBoxManager, ConnectionTester, GeoLocator
 
class SimpleProxyTester:
    """Детальный однопоточный тестер прокси"""
    
    def __init__(self, config_file='option.ini'):
        self.config = Config(config_file)
        self.config.validate_singbox()
        
        # Переопределяем тестовый URL для простого тестера
        self.test_url = "https://httpbin.org/ip"
        self.test_timeout = 5
        
        print(f"⚙️  Sing-box: {self.config.singbox_path}")
        print(f"🌐 Тестовый URL: {self.test_url}")
        print(f"⏱️  Таймаут: {self.test_timeout}с")
    
    def create_simple_config(self, proxy_config, local_port):
        """Минимальный конфиг для тестирования одного прокси"""
        config = {
            "log": {
                "level": "info",
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
        """Тест соединения с правильным получением IP"""
        
        proxy_dict = {
            'http': f'socks5://127.0.0.1:{local_port}',
            'https': f'socks5://127.0.0.1:{local_port}'
        }
        
        # Используем простой и надежный сервис
        test_url = "https://api.ipify.org"
        
        try:
            response = requests.get(
                test_url,
                proxies=proxy_dict,
                timeout=self.test_timeout,
                verify=False
            )
            
            if response.status_code == 200:
                ip = response.text.strip()
                if ip and len(ip.split('.')) == 4:  # Проверяем что это похоже на IPv4
                    print(f"    ✅ Получен IP: {ip}")
                    return True, ip
                else:
                    print(f"    ⚠️  Получен некорректный IP: {ip}")
                    return False, None
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
            
            
    
    def check_proxy(self, proxy_url, port, index=None, total=None):
        """Проверяем одну прокси детально"""
        if index is not None and total is not None:
            print(f"\n🔍 [{index}/{total}] {proxy_url[:60]}...")
        else:
            print(f"\n🔍 {proxy_url[:60]}...")
        
        # Парсим прокси
        parsed = urlparse(proxy_url)
        proxy_config = ProxyParser.parse(proxy_url)
        
        if not proxy_config:
            print("    ⚠️  Не удалось распарсить")
            return None
        
        # Устанавливаем тег
        proxy_config["tag"] = "proxy"
        
        # Создаем конфиг
        config = self.create_simple_config(proxy_config, port)
        
        # Сохраняем конфиг для отладки (опционально)
        debug_mode = True
        config_filename = None
        
        if debug_mode:
            config_filename = f"debug_{port}.json"
            with open(config_filename, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            print(f"    📄 Конфиг: {config_filename}")
        
        # Запускаем sing-box
        startupinfo = None
        if self.config.is_windows:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # Используем SingBoxManager для запуска
        process = SingBoxManager.start_process(
            self.config.singbox_path, 
            config, 
            startupinfo
        )
        
        if not process:
            print("    ❌ Не удалось запустить sing-box")
            return None
        
        print("    ⏳ Запускаю sing-box...")
        time.sleep(2)
        
        # Проверяем запустился ли
        if process.poll() is not None:
            stderr = process.stderr.read()
            print(f"    ❌ Sing-box упал: {stderr[:100]}")
            
            # Сохраняем логи ошибок
            with open(f"error_{port}.log", 'w') as f:
                f.write(stderr)
            
            SingBoxManager.stop_process(process)
            return None
        
        print("    ✅ Sing-box запущен")
        
        # Тестируем соединение
        success, ip = self.test_connection(port)
        
        # Останавливаем процесс
        SingBoxManager.stop_process(process)
        
        # Удаляем временные файлы
        if debug_mode and config_filename and os.path.exists(config_filename):
            try:
                os.unlink(config_filename)
            except:
                pass
        
        if success and ip:
            # Получаем детальную информацию о геолокации
            geo_info = GeoLocator.get_geo_info(ip)
            
            print(f"    🌍 Страна: {geo_info['country']}")
            print(f"    🏢 Провайдер: {geo_info['isp']}")
            if geo_info['city']:
                print(f"    🏙️  Город: {geo_info['city']}")
            
            # Генерируем имя файла
            timestamp = datetime.now().strftime("%m%d_%H%M")
            country_safe = geo_info['country'].replace(' ', '_').replace(',', '')
            filename = f"{country_safe}_{ip.split('.')[-2]}_{timestamp}.txt"
            
            return {
                'proxy': proxy_url,
                'filename': filename,
                'ip': ip,
                'country': geo_info['country'],
                'isp': geo_info['isp'],
                'city': geo_info['city'],
                'geo_info': geo_info
            }
        
        return None if not success else {
            'proxy': proxy_url,
            'filename': f"proxy_{ip}_{datetime.now().strftime('%m%d_%H%M')}.txt",
            'ip': ip,
            'country': 'Unknown',
            'isp': 'Unknown',
            'city': '',
            'geo_info': None
        }
    
    def run(self, input_file):
        """Запуск проверки из файла"""
        print(f"\n📄 Читаю файл: {input_file}")
        
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"❌ Ошибка чтения файла: {e}")
            return []
        
        print(f"📊 Всего прокси для проверки: {len(lines)}")
        print("-" * 60)
        
        successful = []
        port = 16000
        
        for i, proxy_url in enumerate(lines, 1):
            result = self.check_proxy(proxy_url, port, i, len(lines))
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
                    f.write(f"# Город: {result['city']}\n")
                    f.write(f"# Провайдер: {result['isp']}\n\n")
                    f.write(result['proxy'] + "\n")
                
                print(f"    💾 Сохранено: {filepath}")
            
            # Пауза между проверками
            if i < len(lines):
                time.sleep(1)
        
        # Отчет
        print(f"\n{'='*60}")
        print("📊 ИТОГИ ДЕТАЛЬНОЙ ПРОВЕРКИ:")
        print(f"✅ Рабочих: {len(successful)}/{len(lines)}")
        
        if successful:
            print("\n🌍 Найденные прокси:")
            for proxy in successful:
                print(f"  • {proxy['country']} ({proxy['ip']}): {proxy['isp'][:30]}")
            
            # Создаем общий файл
            summary_file = f"working_detailed_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(f"# Детальная проверка прокси ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')})\n")
                f.write(f"# Найдено: {len(successful)} из {len(lines)}\n\n")
                for proxy in successful:
                    f.write(f"# {proxy['country']} - {proxy['city']} - {proxy['isp'][:40]}\n")
                    f.write(proxy['proxy'] + "\n\n")
            
            print(f"\n📋 Сводный файл: {summary_file}")
        
        return successful

def main():
    """Точка входа для простого тестера"""
    print("🔧 ДЕТАЛЬНАЯ ПРОВЕРКА ПРОКСИ")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("Использование: python simple_tester.py <файл_с_прокси>")
        print("Пример: python simple_tester.py working_proxies.txt")
        print("\nПримечание: Лучше использовать с уже проверенными рабочими прокси")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    if not os.path.exists(input_file):
        print(f"❌ Файл не найден: {input_file}")
        sys.exit(1)
    
    tester = SimpleProxyTester()
    tester.run(input_file)
    
    print("\n🎉 Готово!")

if __name__ == '__main__':
    main()