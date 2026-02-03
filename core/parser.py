# core/parser.py
import json
import base64
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Any
 
class ProxyParser:
    """Парсер прокси-ссылок различных протоколов"""
    
    @staticmethod
    def parse(url: str) -> Optional[Dict[str, Any]]:
        """Основной метод парсинга прокси URL"""
        url = url.strip()
        if not url or url.startswith('#'):
            return None
        
        try:
            if '#' in url:
                url = url.split('#')[0]
            
            parsed = urlparse(url)
            protocol = parsed.scheme.lower()
            
            if protocol == 'vless':
                return ProxyParser._parse_vless(url, parsed)
            elif protocol == 'vmess':
                return ProxyParser._parse_vmess(url, parsed)
            elif protocol == 'trojan':
                return ProxyParser._parse_trojan(url, parsed)
            elif protocol == 'ss':
                return ProxyParser._parse_shadowsocks(url, parsed)
            elif protocol == 'hy2':
                return ProxyParser._parse_hysteria2(url, parsed)
            else:
                return None
        except Exception as e:
            # print(f"Ошибка парсинга {url[:50]}: {e}")
            return None
    
    @staticmethod
    def _parse_vless(url: str, parsed: urlparse) -> Optional[Dict[str, Any]]:
        """Парсер VLESS протокола"""
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
        
        # Фильтр неподдерживаемых
        if network in ['xhttp', 'httpupgrade', 'vision', 'splithttp', 'kcp']:
            return None
        
        # Transport настройки
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
        
        # TLS настройки
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
    
    @staticmethod
    def _parse_vmess(url: str, parsed: urlparse) -> Optional[Dict[str, Any]]:
        """Парсер VMess протокола"""
        # Пробуем декодировать из base64
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
                }
                
                net = vmess_config.get('net', 'tcp')
                
                if net in ['kcp', 'quic']:
                    return None
                
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
        
        # Альтернативный парсинг из query параметров
        query = parse_qs(parsed.query)
        config = {
            "type": "vmess",
            "tag": "proxy",
            "server": parsed.hostname,
            "server_port": int(parsed.port) if parsed.port else 443,
            "uuid": parsed.username,
            "security": "auto"
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
    
    @staticmethod
    def _parse_trojan(url: str, parsed: urlparse) -> Optional[Dict[str, Any]]:
        """Парсер Trojan протокола"""
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
    
    @staticmethod
    def _parse_shadowsocks(url: str, parsed: urlparse) -> Optional[Dict[str, Any]]:
        """Парсер Shadowsocks протокола"""
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
    
    @staticmethod
    def _parse_hysteria2(url: str, parsed: urlparse) -> Optional[Dict[str, Any]]:
        """Парсер Hysteria2 протокола"""
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