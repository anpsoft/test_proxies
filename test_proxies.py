# test_proxies.py
#!/usr/bin/env python3
 
import os
import sys
import json
import time
import subprocess
import configparser
import requests
import threading
import queue
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import warnings
import tempfile
import concurrent.futures
 
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
 
class FastProxyTester:
    def __init__(self, config_file='option.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        
        self.test_url = self.config.get('test', 'url', fallback='https://httpbin.org/ip')
        self.max_delay = self.config.getint('test', 'max_delay', fallback=3000)
        self.attempts = self.config.getint('test', 'attempts', fallback=2)
        self.threads = self.config.getint('test', 'threads', fallback=5)
        self.batch_size = self.config.getint('test', 'batch_size', fallback=50)
        
        self.is_windows = os.name == 'nt'
                
        # Путь к sing-box
        if self.is_windows:
            # Только на Windows читаем путь из ini
            configured_path = self.config.get('paths', 'singbox_path', fallback='').strip()
            if configured_path:
                self.singbox_path = configured_path
            else:
                self.singbox_path = 'sing-box.exe'
        else:
            # На Linux всегда ./sing-box
            self.singbox_path = './sing-box'
        
        print(f"⚙️  Используем: {self.singbox_path}")                
                    
                
            
            
        
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        
        self.stats = {}

    
    
    def parse_proxy_url(self, url):
        url = url.strip()
        if not url or url.startswith('#'):
            return None
            
        try:
            if '#' in url:
                url = url.split('#')[0]
            
            parsed = urlparse(url)
            protocol = parsed.scheme.lower()
            
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
                return None
        except Exception as e:
            return None
    
    def _parse_vless(self, url, parsed):
        query = parse_qs(parsed.query)
        
        config = {
            "type": "vless",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": int(parsed.port) if parsed.port else 443,
            "uuid": parsed.username,
            "flow": query.get('flow', [''])[0] or "",
        }
        
        network = query.get('type', ['tcp'])[0]
        
        if network in ['xhttp', 'httpupgrade', 'vision', 'splithttp']:
            return None
        
        if network == "ws":
            config["transport"] = {
                "type": "ws",
                "path": query.get('path', ['/'])[0],
                "headers": {}
            }
            if query.get('host'):
                config["transport"]["headers"]["Host"] = query.get('host', [''])[0]
        elif network == "grpc":
            config["transport"] = {
                "type": "grpc",
                "service_name": query.get('serviceName', [''])[0] or ""
            }
        elif network == "h2":
            config["transport"] = {
                "type": "http",
                "host": [query.get('host', [''])[0]] if query.get('host') else [],
                "path": query.get('path', ['/'])[0]
            }
        elif network != 'tcp':
            config["network"] = network
                
        security = query.get('security', [''])[0]
        if security in ['tls', 'reality', 'xtls']:
            tls_config = {
                "enabled": True,
                "server_name": query.get('sni', [''])[0] or parsed.hostname,
                "insecure": query.get('allowInsecure', ['0'])[0] == '1',
            }
            
            if security == 'reality':
                tls_config["reality"] = {
                    "enabled": True,
                    "public_key": query.get('pbk', [''])[0] or "",
                    "short_id": query.get('sid', [''])[0] or ""
                }
                tls_config["utls"] = {
                    "enabled": True,
                    "fingerprint": query.get('fp', ['chrome'])[0] or "chrome"
                }
            
            config["tls"] = tls_config
        
        return config
    
    def _parse_vmess(self, url, parsed):
        import base64
        
        if len(parsed.username) > 50:
            try:
                padding = 4 - len(parsed.username) % 4
                if padding != 4:
                    username = parsed.username + '=' * padding
                else:
                    username = parsed.username
                    
                decoded = base64.b64decode(username).decode('utf-8')
                vmess_config = json.loads(decoded)
                
                config = {
                    "type": "vmess",
                    "tag": "proxy",
                    "server": vmess_config.get('add'),
                    "server_port": int(vmess_config.get('port', 443)),
                    "uuid": vmess_config.get('id'),
                    "security": vmess_config.get('scy', 'auto')
                    # "alterId": int(vmess_config.get('aid', 0))
                }
                
                net = vmess_config.get('net', 'tcp')
                if net == 'ws':
                    config["transport"] = {
                        "type": "ws",
                        "path": vmess_config.get('path', '/'),
                        "headers": {}
                    }
                    if vmess_config.get('host'):
                        config["transport"]["headers"]["Host"] = vmess_config.get('host')
                
                tls = vmess_config.get('tls', 'none')
                if tls == 'tls':
                    config["tls"] = {
                        "enabled": True,
                        "server_name": vmess_config.get('sni', vmess_config.get('add'))
                    }
                
                return config
            except:
                pass
        
        query = parse_qs(parsed.query)
        config = {
            "type": "vmess",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": int(parsed.port) if parsed.port else 443,
            "uuid": parsed.username,
            "security": "auto"
            # "alterId": 0
        }
        
        if query.get('type', ['tcp'])[0] == 'ws':
            config["transport"] = {
                "type": "ws",
                "path": query.get('path', ['/'])[0],
                "headers": {}
            }
            if query.get('host'):
                config["transport"]["headers"]["Host"] = query.get('host', [''])[0]
        
        if query.get('security', [''])[0] == 'tls':
            config["tls"] = {
                "enabled": True,
                "server_name": query.get('sni', [''])[0] or parsed.hostname
            }
        
        return config
    
    def _parse_trojan(self, url, parsed):
        query = parse_qs(parsed.query)
        
        config = {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": int(parsed.port) if parsed.port else 443,
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
                "headers": {}
            }
            if query.get('host'):
                config["transport"]["headers"]["Host"] = query.get('host', [''])[0]
                
        return config
    
    def _parse_shadowsocks(self, url, parsed):
        import base64
        
        try:
            padding = 4 - len(parsed.username) % 4
            if padding != 4:
                auth_part = parsed.username + '=' * padding
            else:
                auth_part = parsed.username
            decoded = base64.b64decode(auth_part).decode('utf-8')
            method, password = decoded.split(':', 1)
        except:
            if ':' in parsed.username:
                parts = parsed.username.split(':')
                method = parts[0]
                password = ':'.join(parts[1:])
            else:
                method = 'chacha20-ietf-poly1305'
                password = parsed.username
        
        config = {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": int(parsed.port) if parsed.port else 443,
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
            "server_port": int(parsed.port) if parsed.port else 443,
            "password": parsed.username,
            "tls": {
                "enabled": True,
                "server_name": query.get('sni', [''])[0] or parsed.hostname,
                "insecure": query.get('insecure', ['0'])[0] == '1' or 
                            query.get('allowInsecure', ['0'])[0] == '1'
            }
        }
        
        return config
    
    def create_batch_config(self, proxy_configs, base_port=20000):
        """Создать конфиг для тестирования пачки прокси"""
        config = {
            "log": {
                "level": "error",
                "output": "/dev/null" if not self.is_windows else "nul"
            },
            "inbounds": [],
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ],
            "route": {
                "rules": [
                    {"protocol": "dns", "outbound": "direct"}
                ]
            }
        }
        
        # Добавляем inbound для каждого прокси
        for i, proxy_config in enumerate(proxy_configs):
            if proxy_config is None:
                continue
                
            port = base_port + i
            proxy_tag = f"proxy-{i}"
            
            # inbound для этого прокси
            config["inbounds"].append({
                "type": "mixed",
                "tag": f"inbound-{i}",
                "listen": "127.0.0.1",
                "listen_port": port,
                "sniff": False
            })
            
            # outbound для этого прокси
            proxy_config["tag"] = proxy_tag
            config["outbounds"].append(proxy_config)
            
            # правило маршрутизации
            config["route"]["rules"].append({
                "inbound": [f"inbound-{i}"],
                "outbound": proxy_tag
            })
        
        # Финальное правило для всего остального
        config["route"]["final"] = "direct"
        
        return config
    
    def test_batch_proxies(self, proxy_urls, batch_num, total_batches):
        """Тестировать пачку прокси в одном sing-box процессе"""
        print(f"\n🔧 Пакет {batch_num}/{total_batches} ({len(proxy_urls)} прокси)")
        
        # Парсим все прокси в пачке
        proxy_configs = []
        valid_indices = []
        
        for i, url in enumerate(proxy_urls):
            config = self.parse_proxy_url(url)
            proxy_configs.append(config)
            if config:
                valid_indices.append(i)
        
        if not valid_indices:
            print("  ⚠️  Нет валидных прокси в пачке")
            return []
        
        # Создаем конфиг для всей пачки
        base_port = 20000 + (batch_num - 1) * 1000
        batch_config = self.create_batch_config(proxy_configs, base_port)
        
        # Сохраняем конфиг
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(batch_config, f, indent=2)
            config_file = f.name
        
        process = None
        results = []
        

            
            
        try:
            # Retry логика при занятых портах
            startupinfo = None
            if self.is_windows:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            
            MAX_RETRIES = 3
            process = None
            
            for retry in range(MAX_RETRIES):
                print(f"  🚀 Запускаю sing-box (порты {base_port}-{base_port + len(proxy_urls) - 1})...")
                
                process = subprocess.Popen(
                    [self.singbox_path, 'run', '-c', config_file],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                    text=True,
                    encoding='utf-8'
                )
                
                time.sleep(0.5)
                
                if process.poll() is not None:
                    stderr = process.stderr.read()
                    if "address already in use" in stderr and retry < MAX_RETRIES - 1:
                        print(f"  ⚠️ Порт занят, повтор {retry+2}/{MAX_RETRIES}...")
                        time.sleep(2)
                        continue
                    else:
                        print(f"  ❌ Не запустился: {stderr[:200]}")
                        break
                else:
                    time.sleep(2.5)
                    break
            
            if process is None or process.poll() is not None:
                return []
            
            print(f"  ✅ Sing-box запущен, тестирую...")            
            
            
            
            # Тестируем каждый валидный прокси
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_index = {}
                
                for i in valid_indices:
                    port = base_port + i
                    proxy_url = proxy_urls[i]
                    future = executor.submit(self._test_proxy_connection, port, proxy_url)
                    future_to_index[future] = (i, proxy_url)
                
                # Собираем результаты
                for future in concurrent.futures.as_completed(future_to_index):
                    i, proxy_url = future_to_index[future]
                    try:
                        success, delay, message = future.result(timeout=self.max_delay/1000 + 2)
                        results.append((i, proxy_url, success, delay, message))
                        
                        # Выводим результат
                        proxy_id = proxy_url.split('@')[1].split(':')[0] if '@' in proxy_url else "unknown"
                        print(f"  [{i+1:3d}] {proxy_id}: {message}")
                        
                    except concurrent.futures.TimeoutError:
                        proxy_id = proxy_url.split('@')[1].split(':')[0] if '@' in proxy_url else "unknown"
                        print(f"  [{i+1:3d}] {proxy_id}: ⏱️ Таймаут теста")
                        results.append((i, proxy_url, False, 0, "⏱️ Таймаут теста"))
                    except Exception as e:
                        proxy_id = proxy_url.split('@')[1].split(':')[0] if '@' in proxy_url else "unknown"
                        print(f"  [{i+1:3d}] {proxy_id}: ❌ Ошибка: {e}")
                        results.append((i, proxy_url, False, 0, f"❌ Ошибка: {e}"))
            
            # Сортируем по индексу
            results.sort(key=lambda x: x[0])
            
            # Собираем рабочие прокси
            working = [url for i, url, success, delay, msg in results if success]
            
            print(f"  📊 Работает: {len(working)}/{len(valid_indices)}")
            return working
            
        except Exception as e:
            print(f"  ❌ Ошибка пачки: {e}")
            return []
        finally:
            # Останавливаем sing-box
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            # Удаляем временный файл
            try:
                os.unlink(config_file)
            except:
                pass
    
    def _test_proxy_connection(self, port, proxy_url):
        """Тест подключения через указанный порт"""
        best_delay = float('inf')
        last_error = ""
        
        for attempt in range(self.attempts):
            try:
                start_time = time.time()
                
                # ОТЛАДКА: какая схема используется
                proxy_dict = {
                    'http': f'socks5://127.0.0.1:{port}',
                    'https': f'socks5://127.0.0.1:{port}'
                }
                
                #print(f"  🐛 DEBUG proxy_dict: {proxy_dict}")                
                    
                    
             
             
                
                response = requests.get(
                    self.test_url,
                    proxies={
                        'http': f'socks5://127.0.0.1:{port}',
                        'https': f'socks5://127.0.0.1:{port}'
                    },
                    timeout=self.max_delay/1000,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                elapsed = (time.time() - start_time) * 1000
                
                if response.status_code < 400:
                    if elapsed < best_delay:
                        best_delay = elapsed
                    if elapsed <= self.max_delay:
                        return True, elapsed, f"✅ {elapsed:.0f}ms"
                    else:
                        last_error = f"⚠️  {elapsed:.0f}ms > {self.max_delay}ms"
                else:
                    last_error = f"⚠️  HTTP {response.status_code}"
                    
            except requests.exceptions.ConnectTimeout:
                last_error = "⌛ Таймаут"
            except requests.exceptions.ConnectionError as e:
                if "10061" in str(e) or "refused" in str(e).lower():
                    last_error = "🔌 Нет соединения"
                elif "timed out" in str(e).lower():
                    last_error = "⌛ Таймаут"
                else:
                    last_error = f"🔌 Ошибка: {type(e).__name__}"
            except requests.exceptions.ReadTimeout:
                last_error = "⏱️ ReadTimeout"
            except requests.exceptions.ProxyError:
                last_error = "🔄 Ошибка прокси"
            except Exception as e:
                last_error = f"⚠️  {type(e).__name__}"
            
            if attempt < self.attempts - 1:
                time.sleep(0.5)
        
        if best_delay != float('inf'):
            return False, best_delay, f"❌ {best_delay:.0f}ms > {self.max_delay}ms"
        else:
            return False, 0, last_error or "❌ Не удалось"
    
    def process_file(self, input_file):
        """Обработка файла с прокси"""
        filename = os.path.basename(input_file)
        print(f"\n{'='*60}")
        print(f"📄 Файл: {filename}")
        print(f"{'='*60}")
        
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"❌ Ошибка чтения: {e}")
            return []
        
        if not lines:
            print("⚠️  Файл пуст")
            return []
        
        print(f"📊 Всего прокси: {len(lines)}")
        print(f"⚡ Размер пачки: {self.batch_size}")
        print(f"🧵 Потоков: {self.threads}")
        
        # Разбиваем на пачки
        all_working = []
        total_batches = (len(lines) + self.batch_size - 1) // self.batch_size
        
        file_start_time = time.time()
        
        for batch_num in range(total_batches):
            start_idx = batch_num * self.batch_size
            end_idx = min(start_idx + self.batch_size, len(lines))
            batch = lines[start_idx:end_idx]
            
            working = self.test_batch_proxies(batch, batch_num + 1, total_batches)
            all_working.extend(working)
        
        file_elapsed = time.time() - file_start_time

        # Выводим время тестирования (без подготовки)
        testing_time = file_elapsed # - 3  # минус 3 секунды на запуск sing-box
        if testing_time > 0:
            print(f"⏱️  Чистое время тестирования: {testing_time:.1f} сек")
            print(f"⚡ Реальная скорость: {len(lines)/testing_time:.1f} прокси/сек")
        
        self.stats[filename] = {'total': len(lines), 'working': len(all_working)}
        
        # Сохраняем результаты
        if all_working:
            os.makedirs('out', exist_ok=True)
            output_file = f"out/{filename}"
            
            print (output_file )
            print(f"📁 Полный путь: {os.path.abspath(output_file)}")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_working))
                print ( "saved" )
                
            print(f"\n💾 Сохранено: {len(all_working)}/{len(lines)}")
            print(f"📁 Файл: {output_file}")
        else:
            print(f"\n⚠️  Нет рабочих прокси")
        
        return all_working
    
    
    
    def send_telegram_report(self):
        """Отправка архива с результатами в Telegram"""
        if not self.bot_token or not self.chat_id:
            print("⚠️  Telegram токены не настроены")
            return
        
        # Создаём архив
        import zipfile
        zip_path = 'out/results.zip'
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for file in Path('out').glob('*'):
                if file.is_file() and file.suffix != '.zip':
                    zipf.write(file, file.name)
        
        # Отправляем
        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
        with open(zip_path, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': self.chat_id, 'caption': f"✅ Результаты: {len(self.stats)} файлов"}
            requests.post(url, files=files, data=data)
        
        print("📤 Архив отправлен в Telegram")
    
    
    def run(self):
        """Основной процесс"""
        print("🚀 ЗАПУСК БЫСТРОГО ТЕСТИРОВАНИЯ")
        print(f"📊 Потоков: {self.threads}")
        print(f"📦 Размер пачки: {self.batch_size}")
        print(f"🌐 Тестовый URL: {self.test_url}")
        print(f"⏱️  Таймаут: {self.max_delay}мс")
        print(f"🔄 Попыток: {self.attempts}")
        
        # Проверяем sing-box
        if not os.path.exists(self.singbox_path):
            print(f"\n❌ {self.singbox_path} не найден!")
            print("Скачайте с: https://github.com/SagerNet/sing-box/releases")
            return
        
        # Проверяем папку in
        if not os.path.exists('in'):
            print("\n⚠️  Создаю папку 'in'")
            os.makedirs('in', exist_ok=True)
            return
        
        files = list(Path('in').glob('*'))
        if not files:
            print("\n⚠️  Нет файлов в папке 'in'")
            return
        
        start_time = time.time()
        
        all_working = []
        for file in files:
            if file.is_file():
                working = self.process_file(str(file))
                all_working.extend(working)
        
        elapsed_time = time.time() - start_time
        
        # Статистика
        print(f"\n{'='*60}")
        print("📊 ИТОГИ:")
        print(f"{'='*60}")
        
        total_all = sum(s['total'] for s in self.stats.values())
        working_all = sum(s['working'] for s in self.stats.values())
        
        for filename, stats in self.stats.items():
            percent = (stats['working'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"📁 {filename}: {stats['working']}/{stats['total']} ({percent:.1f}%)")
        
        print(f"\n✅ Всего рабочих: {working_all}/{total_all}")
        print(f"⏱️  Общее время: {elapsed_time:.1f} секунд")
        print(f"⚡ Скорость: {total_all/elapsed_time:.2f} прокси/сек")
        
        if total_all > 0:
            print(f"🏎️  Эффективность: {working_all/total_all*100:.1f}% рабочих")
        
        print(f"{'='*60}")
        
        self.send_telegram_report()  

if __name__ == '__main__':
    tester = FastProxyTester()
    tester.run()
