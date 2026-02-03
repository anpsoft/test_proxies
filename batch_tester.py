#!/usr/bin/env python3
# batch_tester.py - Многопоточный тестер прокси (бывший test_proxies.py)
 
import os
import sys
import json
import time
import tempfile
import concurrent.futures
from pathlib import Path
from datetime import datetime
import warnings
 
import requests
 
from core import Config, ProxyParser, SingBoxManager
 
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
 
class BatchProxyTester:
    """Многопоточный тестер прокси с batch-обработкой"""
    
    def __init__(self, config_file='option.ini'):
        self.config = Config(config_file)
        self.config.validate_singbox()
        
        self.stats = {}
        self.failed_batches = []
        
        print(f"⚙️  Используем: {self.config.singbox_path}")
        print(f"📊 Потоков: {self.config.threads}")
        print(f"📦 Размер пачки: {self.config.batch_size}")
        print(f"🌐 Тестовый URL: {self.config.test_url}")
        print(f"⏱️  Таймаут: {self.config.max_delay}мс")
        print(f"🔄 Попыток: {self.config.attempts}")
    
    def create_batch_config(self, proxy_configs, base_port=10000):
        """Создать конфиг для тестирования пачки прокси"""
        config = {
            "log": {
                "level": "error",
                "output": "/dev/null" if not self.config.is_windows else "nul"
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
    
    def _test_proxy_connection(self, port, proxy_url):
        """Тест подключения через указанный порт"""
        best_delay = float('inf')
        last_error = ""
        
        for attempt in range(self.config.attempts):
            try:
                start_time = time.time()
                
                response = requests.get(
                    self.config.test_url,
                    proxies={
                        'http': f'socks5://127.0.0.1:{port}',
                        'https': f'socks5://127.0.0.1:{port}'
                    },
                    timeout=self.config.max_delay/1000,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                elapsed = (time.time() - start_time) * 1000
                
                if response.status_code < 400:
                    if elapsed < best_delay:
                        best_delay = elapsed
                    if elapsed <= self.config.max_delay:
                        return True, elapsed, f"✅ {elapsed:.0f}ms"
                    else:
                        last_error = f"⚠️  {elapsed:.0f}ms > {self.config.max_delay}ms"
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
            
            if attempt < self.config.attempts - 1:
                time.sleep(0.5)
        
        if best_delay != float('inf'):
            return False, best_delay, f"❌ {best_delay:.0f}ms > {self.config.max_delay}ms"
        else:
            return False, 0, last_error or "❌ Не удалось"
    
    def test_batch_proxies(self, proxy_urls, batch_num, total_batches, global_start_idx=0):
        """Тестировать пачку прокси в одном sing-box процессе"""
        print(f"\n🔧 Пакет {batch_num}/{total_batches} ({len(proxy_urls)} прокси)")
        
        # Парсим все прокси в пачке
        proxy_configs = []
        valid_indices = []
        
        for i, url in enumerate(proxy_urls):
            config = ProxyParser.parse(url)
            proxy_configs.append(config)
            if config:
                valid_indices.append(i)
        
        if not valid_indices:
            print("  ⚠️  Нет валидных прокси в пачке")
            return []
        
        # Создаем конфиг для всей пачки
        base_port = 10000 + (batch_num - 1) * self.config.batch_size
        
        batch_config = self.create_batch_config(proxy_configs, base_port)
        
        # Сохраняем конфиг во временный файл
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            json.dump(batch_config, f, indent=2)
            config_file = f.name
        
        process = None
        results = []
        
        try:
            # Retry логика при занятых портах
            startupinfo = None
            if self.config.is_windows:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            
            MAX_RETRIES = 3
            
            for retry in range(MAX_RETRIES):
                print(f"  🚀 Запускаю sing-box (порты {base_port}-{base_port + len(proxy_urls) - 1})...")
                
                import subprocess
                process = subprocess.Popen(
                    [self.config.singbox_path, 'run', '-c', config_file],
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
                        print(f"  ⚠️  Порт занят, повтор {retry+2}/{MAX_RETRIES}...")
                        time.sleep(2)
                        continue
                    else:
                        print(f"  ❌ Не запустился: {stderr[:200]}")
                        break
                else:
                    time.sleep(2.5)
                    break
            
            if process is None or process.poll() is not None:
                self.failed_batches.append(batch_num) 
                return []
            
            print(f"  ✅ Sing-box запущен, тестирую...")            
            
            # Тестируем каждый валидный прокси
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
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
                        success, delay, message = future.result(timeout=self.config.max_delay/1000 + 2)
                        results.append((i, proxy_url, success, delay, message))
                        
                        # Выводим результат
                        global_idx = global_start_idx + i + 1
                        proxy_id = proxy_url.split('@')[1].split(':')[0] if '@' in proxy_url else "unknown"
                        print(f"  [{global_idx:4d}] {proxy_id}: {message}")
                                                
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
                SingBoxManager.stop_process(process)
            
            # Удаляем временный файл
            try:
                os.unlink(config_file)
            except:
                pass
    
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
        print(f"⚡ Размер пачки: {self.config.batch_size}")
        print(f"🧵 Потоков: {self.config.threads}")
        
        # Разбиваем на пачки
        all_working = []
        total_batches = (len(lines) + self.config.batch_size - 1) // self.config.batch_size
        
        file_start_time = time.time()
        
        for batch_num in range(total_batches):
            start_idx = batch_num * self.config.batch_size
            end_idx = min(start_idx + self.config.batch_size, len(lines))
            batch = lines[start_idx:end_idx]
            
            working = self.test_batch_proxies(batch, batch_num + 1, total_batches, start_idx)
            all_working.extend(working)
        
        file_elapsed = time.time() - file_start_time

        # Выводим время тестирования
        if file_elapsed > 0:
            print(f"⏱️  Чистое время тестирования: {file_elapsed:.1f} сек")
            print(f"⚡ Реальная скорость: {len(lines)/file_elapsed:.1f} прокси/сек")
        
        self.stats[filename] = {'total': len(lines), 'working': len(all_working)}
        
        # Сохраняем результаты
        if all_working:
            os.makedirs('out', exist_ok=True)
            output_file = f"out/{filename}"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_working))
                
            print(f"\n💾 Сохранено: {len(all_working)}/{len(lines)}")
            print(f"📁 Файл: {output_file}")
        else:
            print(f"\n⚠️  Нет рабочих прокси")
        
        return all_working
    
    def send_telegram_report(self):
        """Отправка архива с результатами в Telegram"""
        if not self.config.bot_token or not self.config.chat_id:
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
        url = f"https://api.telegram.org/bot{self.config.bot_token}/sendDocument"
        with open(zip_path, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': self.config.chat_id, 'caption': f"✅ Результаты: {len(self.stats)} файлов"}
            requests.post(url, files=files, data=data)
        
        print("📤 Архив отправлен в Telegram")
    
    def run(self):
        """Основной процесс"""
        print("\n🚀 ЗАПУСК БЫСТРОГО ТЕСТИРОВАНИЯ")
        print(f"{'='*60}")
        
        # Проверяем папку in
        if not os.path.exists('in'):
            print("\n⚠️  Создаю папку 'in'")
            os.makedirs('in', exist_ok=True)
            print("📁 Положите файлы с прокси в папку 'in/'")
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
        
        if total_all > 0:
            print(f"⚡ Скорость: {total_all/elapsed_time:.2f} прокси/сек")
            print(f"🏎️  Эффективность: {working_all/total_all*100:.1f}% рабочих")
        
        if self.failed_batches:
            print(f"\n⚠️  Сбойных пачек: {len(self.failed_batches)}")
            print(f"📋 Номера: {sorted(set(self.failed_batches))}")
        
        print(f"{'='*60}")
        
        # Отправляем отчет в Telegram
        self.send_telegram_report()

def main():
    """Точка входа"""
    print("🤖 ПАКЕТНЫЙ ТЕСТЕР ПРОКСИ")
    print("📁 Проверяет все файлы из папки in/")
    print(f"{'='*60}")
    
    tester = BatchProxyTester()
    tester.run()

if __name__ == '__main__':
    main()