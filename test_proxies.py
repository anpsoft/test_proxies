#!/usr/bin/env python3
 
# https://github.com/SagerNet/sing-box
 

import os
import sys
import json
import time
import subprocess
import configparser
import requests
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
 
class ProxyTester:
    def __init__(self, config_file='option.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
        self.test_url = self.config.get('test', 'url')
        self.max_delay = self.config.getint('test', 'max_delay')
        self.attempts = self.config.getint('test', 'attempts')
        
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        
        self.stats = {}
        
    def parse_proxy_url(self, url):
        """Парсинг прокси URL в конфиг sing-box"""
        url = url.strip()
        if not url or url.startswith('#'):
            return None
            
        try:
            parsed = urlparse(url)
            protocol = parsed.scheme
            
            if protocol == 'vless':
                return self._parse_vless(url, parsed)
            elif protocol == 'vmess':
                return self._parse_vmess(url, parsed)
            elif protocol == 'trojan':
                return self._parse_trojan(url, parsed)
            elif protocol == 'ss':
                return self._parse_shadowsocks(url, parsed)
            elif protocol == 'hy2':
                return self._parse_hysteria2(url, parsed)
            else:
                print(f"⚠️  Неизвестный протокол: {protocol}")
                return None
        except Exception as e:
            print(f"❌ Ошибка парсинга {url[:50]}...: {e}")
            return None
    
    def _parse_vless(self, url, parsed):
        query = parse_qs(parsed.query)
        
        config = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "uuid": parsed.username,
            "flow": query.get('flow', [''])[0] or "",
            "network": query.get('type', ['tcp'])[0],
            "tls": {
                "enabled": query.get('security', [''])[0] in ['tls', 'reality'],
                "server_name": query.get('sni', [''])[0] or parsed.hostname,
                "insecure": query.get('allowInsecure', ['0'])[0] == '1',
                "reality": {
                    "enabled": query.get('security', [''])[0] == 'reality',
                    "public_key": query.get('pbk', [''])[0]
                } if query.get('security', [''])[0] == 'reality' else {}
            }
        }
        
        # Параметры транспорта
        if config["network"] == "ws":
            config["transport"] = {
                "type": "ws",
                "path": query.get('path', ['/'])[0],
                "headers": {"Host": query.get('host', [''])[0]} if query.get('host') else {}
            }
        elif config["network"] == "http":
            config["transport"] = {
                "type": "http",
                "host": [query.get('host', [''])[0]] if query.get('host') else []
            }
            
        return config
    
    def _parse_vmess(self, url, parsed):
        # VMess использует base64 в username
        import base64
        try:
            decoded = base64.b64decode(parsed.username).decode('utf-8')
            vmess_config = json.loads(decoded)
        except:
            # Альтернативный формат
            query = parse_qs(parsed.query)
            vmess_config = {
                'add': parsed.hostname,
                'port': parsed.port,
                'id': parsed.username,
                'net': query.get('type', ['tcp'])[0],
                'type': query.get('headerType', ['none'])[0],
                'host': query.get('host', [''])[0],
                'path': query.get('path', [''])[0],
                'tls': query.get('security', [''])[0],
                'sni': query.get('sni', [''])[0]
            }
        
        config = {
            "type": "vmess",
            "tag": "proxy",
            "server": vmess_config.get('add'),
            "server_port": int(vmess_config.get('port', 443)),
            "uuid": vmess_config.get('id'),
            "security": vmess_config.get('scy', 'auto'),
            "alter_id": int(vmess_config.get('aid', 0))
        }
        
        if vmess_config.get('net') == 'ws':
            config["transport"] = {
                "type": "ws",
                "path": vmess_config.get('path', '/'),
                "headers": {"Host": vmess_config.get('host', '')} if vmess_config.get('host') else {}
            }
        
        if vmess_config.get('tls') == 'tls':
            config["tls"] = {
                "enabled": True,
                "server_name": vmess_config.get('sni', vmess_config.get('add'))
            }
            
        return config
    
    def _parse_trojan(self, url, parsed):
        query = parse_qs(parsed.query)
        
        config = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
        }
        
        if query.get('security', ['tls'])[0] != 'none':
            config["tls"] = {
                "enabled": True,
                "server_name": query.get('sni', [''])[0] or parsed.hostname,
                "insecure": query.get('allowInsecure', ['0'])[0] == '1'
            }
        
        if query.get('type', ['tcp'])[0] == 'ws':
            config["transport"] = {
                "type": "ws",
                "path": query.get('path', ['/'])[0],
                "headers": {"Host": query.get('host', [''])[0]} if query.get('host') else {}
            }
            
        return config
    
    def _parse_shadowsocks(self, url, parsed):
        import base64
        
        # Декодируем метод и пароль из username
        try:
            decoded = base64.b64decode(parsed.username).decode('utf-8')
            method, password = decoded.split(':', 1)
        except:
            method = parsed.username.split(':')[0] if ':' in parsed.username else 'chacha20-ietf-poly1305'
            password = parsed.username.split(':', 1)[1] if ':' in parsed.username else parsed.username
        
        config = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "method": method,
            "password": password
        }
        
        return config
    
    def _parse_hysteria2(self, url, parsed):
        query = parse_qs(parsed.query)
        
        config = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": parsed.port,
            "password": parsed.username,
            "tls": {
                "enabled": True,
                "server_name": query.get('sni', [''])[0] or parsed.hostname,
                "insecure": query.get('insecure', ['0'])[0] == '1'
            }
        }
        
        return config
    
    def create_singbox_config(self, proxy_config):
        """Создать конфиг sing-box для теста"""
        config = {
            "log": {
                "level": "error"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 10808
                }
            ],
            "outbounds": [
                proxy_config,
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "route": {
                "rules": [],
                "final": "proxy"
            }
        }
        
        return config
    
    def test_proxy(self, proxy_url):
        """Тестирование одного прокси"""
        proxy_config = self.parse_proxy_url(proxy_url)
        if not proxy_config:
            return False, 0
        
        singbox_config = self.create_singbox_config(proxy_config)
        
        # Сохраняем временный конфиг
        config_file = '/tmp/singbox_test.json'
        with open(config_file, 'w') as f:
            json.dump(singbox_config, f)
        
        # Запускаем sing-box
        process = None
        try:
            process = subprocess.Popen(
                ['./sing-box', 'run', '-c', config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Даём время на запуск
            time.sleep(2)
            
            # Проверяем доступность через прокси
            for attempt in range(self.attempts):
                try:
                    start_time = time.time()
                    response = requests.get(
                        self.test_url,
                        proxies={
                            'http': 'http://127.0.0.1:10808',
                            'https': 'http://127.0.0.1:10808'
                        },
                        timeout=self.max_delay / 1000,
                        verify=False
                    )
                    elapsed = (time.time() - start_time) * 1000  # в миллисекундах
                    
                    if response.status_code == 200 and elapsed <= self.max_delay:
                        return True, elapsed
                        
                except requests.exceptions.RequestException as e:
                    if attempt < self.attempts - 1:
                        time.sleep(1)
                    continue
            
            return False, 0
            
        except Exception as e:
            print(f"❌ Ошибка теста: {e}")
            return False, 0
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except:
                    process.kill()
    
    def process_file(self, input_file):
        """Обработка одного файла с прокси"""
        file_name = os.path.basename(input_file)
        print(f"\n📄 Обработка файла: {file_name}")
        
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total = 0
        working = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            total += 1
            print(f"🔍 Тест {total}: {line[:60]}...", end=' ')
            
            success, delay = self.test_proxy(line)
            
            if success:
                print(f"✅ OK ({delay:.0f}ms)")
                working.append(line)
            else:
                print(f"❌ FAIL")
        
        self.stats[file_name] = {'total': total, 'working': len(working)}
        
        # Сохраняем рабочие прокси
        if working:
            output_file = f"out/{file_name}"
            os.makedirs('out', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(working) + '\n')
            print(f"💾 Сохранено: {len(working)}/{total} в {output_file}")
        else:
            print(f"⚠️  Нет рабочих прокси в {file_name}")
        
        return working
    
    def send_telegram_message(self, text):
        """Отправка сообщения в Telegram"""
        if not self.bot_token or not self.chat_id:
            print("⚠️  Telegram не настроен")
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            requests.post(url, data={
                'chat_id': self.chat_id,
                'text': text,
                'parse_mode': 'HTML'
            })
        except Exception as e:
            print(f"❌ Ошибка отправки в Telegram: {e}")
    
    def send_telegram_file(self, file_path):
        """Отправка файла в Telegram"""
        if not self.bot_token or not self.chat_id:
            return
        
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
            with open(file_path, 'rb') as f:
                requests.post(url, data={'chat_id': self.chat_id}, files={'document': f})
        except Exception as e:
            print(f"❌ Ошибка отправки файла: {e}")
    
    def run(self):
        """Основной процесс"""
        print("🚀 Запуск тестирования прокси\n")
        
        # Проверяем наличие sing-box
        if not os.path.exists('./sing-box'):
            print("❌ sing-box не найден!")
            sys.exit(1)
        
        # Создаём папку out
        os.makedirs('out', exist_ok=True)
        
        # Обрабатываем все файлы из in/
        input_files = list(Path('in').glob('*'))
        if not input_files:
            print("⚠️  Нет файлов в папке in/")
            return
        
        for input_file in input_files:
            if input_file.is_file():
                self.process_file(str(input_file))
        
        # Формируем итоговую статистику
        total_all = sum(s['total'] for s in self.stats.values())
        working_all = sum(s['working'] for s in self.stats.values())
        
        summary = "✅ <b>Тест завершён</b>\n\n"
        for file_name, stats in self.stats.items():
            icon = "✓" if stats['working'] > 0 else "✗"
            summary += f"📁 <code>{file_name}</code>: {stats['working']}/{stats['total']} {icon}\n"
        summary += f"\n<b>Всего: {working_all}/{total_all} рабочих</b>"
        
        print("\n" + "="*50)
        print(summary.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', ''))
        
        # Отправляем в Telegram
        self.send_telegram_message(summary)
        
        # Отправляем файлы
        for output_file in Path('out').glob('*'):
            if output_file.is_file():
                print(f"📤 Отправка {output_file.name} в Telegram")
                self.send_telegram_file(str(output_file))
        
        print("\n✨ Готово!")

if __name__ == '__main__':
    tester = ProxyTester()
    tester.run()
