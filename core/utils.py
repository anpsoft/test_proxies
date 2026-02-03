# core/utils.py
import os
import subprocess
import tempfile
import json
import time
from typing import Optional, Dict, Any
 
class SingBoxManager:
    """Менеджер для работы с sing-box"""
    
    @staticmethod
    def start_process(singbox_path: str, config: Dict[str, Any], 
                     startupinfo=None) -> Optional[subprocess.Popen]:
        """Запускает sing-box процесс с конфигурацией"""
        try:
            # Сохраняем конфиг во временный файл
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', 
                                           delete=False, encoding='utf-8') as f:
                json.dump(config, f, indent=2)
                config_file = f.name
            
            # Запускаем процесс
            process = subprocess.Popen(
                [singbox_path, 'run', '-c', config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                text=True,
                encoding='utf-8'
            )
            
            # Даем время на запуск
            time.sleep(1)
            
            # Проверяем запустился ли
            if process.poll() is not None:
                stderr = process.stderr.read()
                print(f"❌ Sing-box не запустился: {stderr[:200]}")
                
                # Удаляем временный файл
                try:
                    os.unlink(config_file)
                except:
                    pass
                return None
            
            return process
            
        except Exception as e:
            print(f"❌ Ошибка запуска sing-box: {e}")
            return None
    
    @staticmethod
    def stop_process(process: subprocess.Popen, timeout: int = 2):
        """Останавливает sing-box процесс"""
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except:
                process.kill()

class ConnectionTester:
    """Базовый класс для тестирования соединений"""
    
    @staticmethod
    def test_proxy_connection(port: int, test_url: str, timeout: float = 5.0) -> tuple:
        """Тестирует подключение через прокси на указанном порту"""
        import requests
        
        proxy_dict = {
            'http': f'socks5://127.0.0.1:{port}',
            'https': f'socks5://127.0.0.1:{port}'
        }
        
        try:
            start_time = time.time()
            response = requests.get(
                test_url,
                proxies=proxy_dict,
                timeout=timeout,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            elapsed = (time.time() - start_time) * 1000
            
            if response.status_code < 400:
                return True, elapsed, f"✅ {elapsed:.0f}ms"
            else:
                return False, elapsed, f"⚠️ HTTP {response.status_code}"
                
        except requests.exceptions.ConnectTimeout:
            return False, 0, "⌛ Таймаут"
        except requests.exceptions.ConnectionError as e:
            if "10061" in str(e) or "refused" in str(e).lower():
                return False, 0, "🔌 Нет соединения"
            elif "timed out" in str(e).lower():
                return False, 0, "⌛ Таймаут"
            else:
                return False, 0, f"🔌 Ошибка: {type(e).__name__}"
        except requests.exceptions.ReadTimeout:
            return False, 0, "⏱️ ReadTimeout"
        except requests.exceptions.ProxyError:
            return False, 0, "🔄 Ошибка прокси"
        except Exception as e:
            return False, 0, f"⚠️ {type(e).__name__}"

class GeoLocator:
    """Класс для определения геолокации IP"""
    
    @staticmethod
    def get_geo_info(ip: str) -> Dict[str, str]:
        """Получает информацию о местоположении IP"""
        import requests
        
        try:
            # Используем ipinfo.io как основной источник
            response = requests.get(
                f"https://ipinfo.io/{ip}/json",
                timeout=3
            )
            
            if response.status_code == 200:
                geo_data = response.json()
                return {
                    'country': geo_data.get('country', 'Unknown'),
                    'country_code': geo_data.get('country', ''),
                    'city': geo_data.get('city', ''),
                    'region': geo_data.get('region', ''),
                    'isp': geo_data.get('org', 'Unknown')[:50],
                    'asn': geo_data.get('org', '').split()[0] if 'org' in geo_data else '',
                    'ip': ip
                }
        except:
            # Резервный вариант
            try:
                response = requests.get(
                    f"http://ip-api.com/json/{ip}",
                    timeout=3
                )
                if response.status_code == 200:
                    geo_data = response.json()
                    if geo_data.get('status') == 'success':
                        return {
                            'country': geo_data.get('country', 'Unknown'),
                            'country_code': '',
                            'city': geo_data.get('city', ''),
                            'region': geo_data.get('regionName', ''),
                            'isp': geo_data.get('isp', 'Unknown')[:50],
                            'asn': geo_data.get('as', ''),
                            'ip': ip
                        }
            except:
                pass
        
        # Если ничего не получилось
        return {
            'country': 'Unknown',
            'country_code': '',
            'city': '',
            'region': '',
            'isp': 'Unknown',
            'asn': '',
            'ip': ip
        }