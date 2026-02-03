# core/config.py
import os
import configparser
from pathlib import Path
 
class Config:
    """Класс для чтения конфигурации из option.ini"""
    
    def __init__(self, config_file='option.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file, encoding='utf-8')
        
        # Путь к sing-box
        self.singbox_path = self._get_singbox_path()
        
        # Настройки тестирования
        self.test_url = self.config.get('test', 'url', fallback='https://httpbin.org/ip')
        self.max_delay = self.config.getint('test', 'max_delay', fallback=3000)
        self.attempts = self.config.getint('test', 'attempts', fallback=2)
        self.threads = self.config.getint('test', 'threads', fallback=10)
        self.batch_size = self.config.getint('test', 'batch_size', fallback=50)
        
        # Флаги системы
        self.is_windows = os.name == 'nt'
        
        # Telegram (опционально)
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    
    def _get_singbox_path(self):
        """Определяет путь к sing-box"""
        if os.name == 'nt':
            # Windows
            configured_path = self.config.get('paths', 'singbox_path', fallback='').strip()
            if configured_path and os.path.exists(configured_path):
                return configured_path
            return 'sing-box.exe'
        else:
            # Linux/Mac
            return './sing-box'
    
    def validate_singbox(self):
        """Проверяет доступность sing-box"""
        if not os.path.exists(self.singbox_path):
            raise FileNotFoundError(
                f"Sing-box не найден: {self.singbox_path}\n"
                "Скачайте с: https://github.com/SagerNet/sing-box/releases"
            )
        return True