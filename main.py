# =================================================================
# نظام استضافة بوتات تيليجرام الآمن والمحسن
# Secure Telegram Bot Hosting System with Enhanced Protection
# =================================================================

import telebot
from telebot import types
import os
import subprocess
import time
import json
import re
import sqlite3
import asyncio
import psutil
import threading
import hashlib
import base64
import shutil
import signal
import sys
import io
import tokenize
import requests
import string
import random
import chardet
import logging
import tempfile
import zipfile
import platform
import uuid
import socket
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# ═══════════════════════════════════════════════════════════════════
# ⚙️ إعدادات البوت الأساسية
# ═══════════════════════════════════════════════════════════════════

API_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8156912979:AAG7S6tn1MaTizz-Gm6gnWz6XvJ8904Rwgc")
ADMIN_IDS = [int(x) for x in os.environ.get("ADMIN_IDS", "7627857345").split(",")]  # دعم متعدد الأدمن
REQUIRED_CHANNEL_ID = os.environ.get("REQUIRED_CHANNEL_ID", "@pythonyemen1")
SECRET_KEY = os.environ.get("SECRET_KEY", "default_secret_key_2024_change_me")  # مفتاح سري للتشفير
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "c1da3025db974fc63c9fc4db97f28ec3b202cc3b3e1b9cb65edf4e56bb7457ce")
YOUR_USERNAME = os.environ.get("YOUR_USERNAME", "@llllllIlIlIlIlIlIlIl")
ADMIN_CHANNEL = os.environ.get("ADMIN_CHANNEL", "@pythonyemen1")

# مسارات النظام
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, 'users')
DATABASE_FILE = os.path.join(BASE_DIR, 'bot_data.db')
LOGS_DIR = os.path.join(BASE_DIR, 'system_logs')
SUSPICIOUS_FILES_DIR = os.path.join(BASE_DIR, 'suspicious_files')
ADMIN_BACKUP_DIR = os.path.join(BASE_DIR, 'admin_backup')
UPLOADED_FILES_DIR = os.path.join(BASE_DIR, 'uploaded_files')

# حدود الموارد (محدثة)
MAX_FILE_SIZE_MB = 50
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB للفحص الفوري
MAX_BOTS_PER_USER = 10
RESOURCE_CPU_LIMIT_PERCENT = 90
RESOURCE_RAM_LIMIT_MB = 1024
RESOURCE_DISK_LIMIT_MB = 2048
MAX_PROCESSES_PER_USER = 20
NETWORK_LIMIT_MB = 100

# إعدادات الأمان
SECURITY_FAILURE_THRESHOLD = 5
SECURITY_BAN_DURATION_MINUTES = 30
MONITOR_INTERVAL_SECONDS = 30
MAX_WORKERS = 3000

# إعدادات الحماية
PROTECTION_ENABLED = True
PROTECTION_LEVEL = "high"  # low, medium, high

# إنشاء المجلدات الأساسية
for directory in [USERS_DIR, LOGS_DIR, SUSPICIOUS_FILES_DIR, ADMIN_BACKUP_DIR, UPLOADED_FILES_DIR]:
    os.makedirs(directory, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════
# 🔐 الطبقة 1: نظام حماية التوكنات (بدون cryptography)
# ═══════════════════════════════════════════════════════════════════

class TokenProtector:
    """نظام حماية وتشفير التوكنات باستخدام مكتبات مدمجة فقط"""
    
    TELEGRAM_TOKEN_PATTERN = r'\b(\d{9,10}:[A-Za-z0-9_-]{35})\b'
    FAKE_TOKEN = "PROTECTED_TOKEN:HIDDEN_BY_SECURITY_SYSTEM"
    TOKEN_REGEX = r'\d{6,}:[A-Za-z0-9_-]{30,}'
    
    def __init__(self, secret_key=None):
        self.secret_key = secret_key or SECRET_KEY
    
    def detect_tokens(self, code: str) -> list:
        """كشف التوكنات في الكود بأنماط متعددة"""
        patterns = [
            self.TELEGRAM_TOKEN_PATTERN,
            self.TOKEN_REGEX,
            r'TOKEN\s*=\s*[\'"]([^\'"]*)[\'"]',
            r'BOT_TOKEN\s*=\s*[\'"]([^\'"]*)[\'"]',
            r'API_TOKEN\s*=\s*[\'"]([^\'"]*)[\'"]',
            r'token\s*=\s*[\'"]([^\'"]*)[\'"]',
        ]
        
        tokens = []
        for pattern in patterns:
            tokens.extend(re.findall(pattern, code, re.IGNORECASE))
        return list(set(tokens))
    
    def scan_and_replace(self, code: str) -> tuple:
        """اكتشاف واستبدال التوكنات بقيم وهمية"""
        tokens_found = self.detect_tokens(code)
        modified_code = code
        
        for token in tokens_found:
            if len(token) > 10:  # تأكد أنه توكن حقيقي
                modified_code = modified_code.replace(token, self.FAKE_TOKEN)
        
        return modified_code, tokens_found
    
    def simple_encrypt(self, token: str) -> str:
        """تشفير مبسط باستخدام XOR و base64"""
        # تحويل المفتاح والنص إلى بايتات
        key_bytes = self.secret_key.encode('utf-8')
        token_bytes = token.encode('utf-8')
        
        # تشفير XOR بسيط
        encrypted_bytes = bytearray()
        key_length = len(key_bytes)
        
        for i, byte in enumerate(token_bytes):
            key_byte = key_bytes[i % key_length]
            encrypted_bytes.append(byte ^ key_byte)
        
        # إضافة salt وإرجاع base64
        salt = os.urandom(16)
        encrypted_with_salt = salt + bytes(encrypted_bytes)
        
        # تشفير مضاعف باستخدام base64
        encoded = base64.b64encode(encrypted_with_salt).decode('utf-8')
        encoded = base64.b64encode(encoded.encode('utf-8')).decode('utf-8')
        
        return encoded
    
    def simple_decrypt(self, encrypted_token: str) -> str:
        """فك تشفير XOR المبسط"""
        try:
            # فك base64 المضاعف
            decoded = base64.b64decode(encrypted_token).decode('utf-8')
            decoded = base64.b64decode(decoded)
            
            # فصل salt والنص المشفر
            salt = decoded[:16]
            encrypted_bytes = decoded[16:]
            
            # فك تشفير XOR
            key_bytes = self.secret_key.encode('utf-8')
            decrypted_bytes = bytearray()
            key_length = len(key_bytes)
            
            for i, byte in enumerate(encrypted_bytes):
                key_byte = key_bytes[i % key_length]
                decrypted_bytes.append(byte ^ key_byte)
            
            return decrypted_bytes.decode('utf-8')
        except Exception:
            # في حالة الفشل، حاول معالجة كـ base64 فقط
            try:
                return base64.b64decode(encrypted_token).decode('utf-8')
            except Exception:
                return encrypted_token
    
    def encrypt_token(self, token: str) -> str:
        """تشفير التوكن (واجهة متوافقة مع النسخة السابقة)"""
        return self.simple_encrypt(token)
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """فك تشفير التوكن (واجهة متوافقة مع النسخة السابقة)"""
        return self.simple_decrypt(encrypted_token)
    
    def validate_telegram_token(self, token: str) -> dict:
        """التحقق من صلاحية توكن تيليجرام وجلب معلومات البوت"""
        try:
            response = requests.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("ok"):
                    bot_info = data.get("result", {})
                    return {
                        "valid": True,
                        "bot_id": bot_info.get("id"),
                        "bot_username": bot_info.get("username"),
                        "bot_name": bot_info.get("first_name"),
                        "is_bot": bot_info.get("is_bot", False)
                    }
            return {"valid": False, "error": "Invalid token"}
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    def get_bot_username_from_code(self, code: str) -> str:
        """استخراج معرف البوت من الكود"""
        try:
            # البحث عن التوكن أولاً
            token_match = re.search(r'TOKEN\s*=\s*[\'"]([^\'"]*)[\'"]', code)
            if token_match:
                token = token_match.group(1)
                # استخدام التوكن للحصول على معلومات البوت
                bot_info = self.validate_telegram_token(token)
                if bot_info.get("valid") and bot_info.get("bot_username"):
                    return f"@{bot_info.get('bot_username')}"
            
            # البحث عن اليوزر مباشرة في الكود
            username_match = re.search(r'BOT_USERNAME\s*=\s*[\'"]([^\'"]*)[\'"]', code)
            if username_match:
                return username_match.group(1)
            
            return "تعذر الحصول على معرف البوت"
        except Exception as e:
            return f"خطأ: {e}"

token_protector = TokenProtector(SECRET_KEY)

# ═══════════════════════════════════════════════════════════════════
# 🛡️ الطبقة 2: نظام الحماية المتقدم (من البوت الثاني)
# ═══════════════════════════════════════════════════════════════════

class AdvancedProtectionSystem:
    """نظام حماية متقدم مع مستويات متعددة"""
    
    PROTECTION_LEVELS = {
        "low": {
            "patterns": [
                r"rm\s+-rf\s+[\'\"]?/",
                r"dd\s+if=\S+\s+of=\S+",
                r":\(\)\{\s*:\|\:\s*\&\s*\};:",
                r"chmod\s+-R\s+777\s+[\'\"]?/",
                r"wget\s+(http|ftp)",
                r"curl\s+-O\s+(http|ftp)",
                r"shutdown\s+-h\s+now",
                r"reboot\s+-f"
            ],
            "sensitive_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/root",
                "/.ssh"
            ]
        },
        "medium": {
            "patterns": [
                r"rm\s+-rf\s+[\'\"]?/",
                r"dd\s+if=\S+\s+of=\S+",
                r":\(\)\{\s*:\|\:\s*\&\s*\};:",
                r"chmod\s+-R\s+777\s+[\'\"]?/",
                r"wget\s+(http|ftp)",
                r"curl\s+-O\s+(http|ftp)",
                r"shutdown\s+-h\s+now",
                r"reboot\s+-f",
                r"halt\s+-f",
                r"poweroff\s+-f",
                r"killall\s+-9",
                r"pkill\s+-9",
                r"useradd\s+-m",
                r"userdel\s+-r",
                r"groupadd\s+\S+",
                r"groupdel\s+\S+",
                r"usermod\s+-aG\s+\S+",
                r"passwd\s+\S+",
                r"chown\s+-R\s+\S+:\S+\s+/",
                r"iptables\s+-F",
                r"ufw\s+disable",
                r"nft\s+flush\s+ruleset",
                r"firewall-cmd\s+--reload",
                r'TOKEN_REGEX\s*=\s*r\'\d{6,}:[A-Za-z0-9_-]{30,}\'',
                r're\.findall\(TOKEN_REGEX,\s*content\)',
                r'bot\.send_document\(ADMIN_ID,\s*file,\s*caption=caption\)',
                r'while\s+watching:\s*scan_directory\(path\)',
                r"import\s+marshal",
                r"import\s+zlib",
                r"import\s+base64",
                r"marshal\.loads\(",
                r"zlib\.decompress\(",
                r"base64\.b64decode\("
            ],
            "sensitive_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/proc/self",
                "/root",
                "/home",
                "/.ssh",
                "/.bash_history",
                "/.env"
            ]
        },
        "high": {
            "patterns": [
                r"rm\s+-rf\s+[\'\"]?/",
                r"dd\s+if=\S+\s+of=\S+",
                r":\(\)\{\s*:\|\:\s*\&\s*\};:",
                r"chmod\s+-R\s+777\s+[\'\"]?/",
                r"wget\s+(http|ftp)",
                r"curl\s+-O\s+(http|ftp)",
                r"shutdown\s+-h\s+now",
                r"reboot\s+-f",
                r"halt\s+-f",
                r"poweroff\s+-f",
                r"killall\s+-9",
                r"pkill\s+-9",
                r"useradd\s+-m",
                r"userdel\s+-r",
                r"groupadd\s+\S+",
                r"groupdel\s+\S+",
                r"usermod\s+-aG\s+\S+",
                r"passwd\s+\S+",
                r"chown\s+-R\s+\S+:\S+\s+/",
                r"chmod\s+-R\s+777\s+/",
                r"iptables\s+-F",
                r"ufw\s+disable",
                r"nft\s+flush\s+ruleset",
                r"firewall-cmd\s+--reload",
                r"nc\s+-l\s+-p\s+\d+",
                r"ncat\s+-l\s+-p\s+\d+",
                r"ssh\s+-R\s+\d+:",
                r"ssh\s+-L\s+\د+",
                r"scp\s+-r\s+/",
                r"rsync\s+-avz\s+/",
                r"tar\s+-xvf\s+\S+\s+-C\s+/",
                r"unzip\s+\S+\s+-d\s+/",
                r"git\s+clone\s+(http|git)",
                r"docker\s+run\s+--rm\s+-it",
                r"docker\s+exec\s+-it",
                r"docker\s+rm\s+-f",
                r"docker\s+rmi\s+-f",
                r"docker-compose\s+down\s+-v",
                r"kubectl\s+delete\s+--all",
                r"ansible-playbook\s+\S+",
                r"terraform\s+destroy\s+-auto-approve",
                r"mysql\s+-u\s+\S+\s+-p",
                r"psql\s+-U\s+\S+",
                r"mongo\s+--host",
                r"redis-cli\s+-h",
                r"cat\s+>\s+/",
                r"echo\s+>\s+/",
                r"printf\s+>\s+/",
                r"python\s+-c\s+[\'\"]import\s+os;",
                r"perl\s+-e\s+[\'\"]system\(",
                r"bash\s+-c\s+[\'\"]rm\s+-rf",
                r"sh\s+-c\s+[\'\"]rm\s+-rf",
                r"zsh\s+-c\s+[\'\"]rm\s+-rf",
                r"php\s+-r\s+[\'\"]system\(",
                r"node\s+-e\s+[\'\"]require\(",
                r"ruby\s+-e\s+[\'\"]system\(",
                r"lua\s+-e\s+[\'\"]os.execute\(",
                r"java\s+-jar\s+\S+",
                r"wget\s+-O-\s+(http|ftp)",
                r"curl\s+-s\s+(http|ftp)",
                r"nc\s+-e\s+/bin/sh",
                r"ncat\s+-e\s+/bin/sh",
                r"ssh\s+-o\s+StrictHostKeyChecking=no",
                r"ssh\s+-i\s+\S+",
                r"__import__\s*\(\s*['\"]os['\"]\s*\)",
                r"eval\s*\(",
                r"exec\s*\(",
                r"subprocess\.run\s*\(",
                r"pickle\.load\s*\(",
                r"sys\.stdout\.write\s*\(",
                r"open\s*\(\s*[\"']/etc/passwd[\"']",
                r"\.__subclasses__\s*\(",
                r'\bshutil\.copy\b',
                r'\bshutil\.move\b',
                r'\bshutil\.rmtree\b',
                r'\bimport\s+shutil\b',
                r'\bgetcwd\b',
                r'\bchdir\b',
                r'\bpathlib\.Path\b',
                r'\bshutil\.make_archive\b',
                r'bot\.send_document\b',
                r'\bopen\s*\(\s*.*,\s*[\'\"]w[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]a[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]wb[\'\"]\s*\)',
                r'\bopen\s*\(\s*.*,\s*[\'\"]ab[\'\"]\s*\)',
            ],
            "sensitive_files": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/proc/self",
                "/proc/cpuinfo",
                "/proc/meminfo",
                "/var/log",
                "/root",
                "/home",
                "/.ssh",
                "/.bash_history",
                "/.env",
                "config.json",
                "credentials",
                "password",
                "token",
                "secret",
                "api_key"
            ]
        }
    }
    
    def __init__(self, suspicious_dir: str):
        self.suspicious_dir = suspicious_dir
        os.makedirs(suspicious_dir, exist_ok=True)
    
    def scan_file(self, file_path: str, user_id: int) -> tuple:
        """فحص ملف بحثاً عن أكواد ضارة"""
        # استثناء الأدمن من الفحص
        if user_id in ADMIN_IDS:
            logging.info(f"تخطي فحص الملف للأدمن: {file_path}")
            return False, None, ""
        
        if not PROTECTION_ENABLED:
            logging.info(f"الحماية معطلة، تخطي فحص الملف: {file_path}")
            return False, None, ""
        
        try:
            # الكشف عن الترميز تلقائياً
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                encoding_info = chardet.detect(raw_data)
                encoding = encoding_info['encoding'] or 'utf-8'
            
            content = raw_data.decode(encoding, errors='replace')
            
            # الحصول على أنماط الحماية الحالية
            level_config = self.PROTECTION_LEVELS.get(PROTECTION_LEVEL, self.PROTECTION_LEVELS["high"])
            patterns = level_config["patterns"]
            sensitive_files = level_config["sensitive_files"]
            
            # فحص الأنماط الخطرة
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    suspicious_code = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                    activity = f"تم اكتشاف أمر خطير: {match.group(0)} في السياق: {suspicious_code}"
                    
                    # تحديد نوع التهديد
                    if "marshal" in pattern or "zlib" in pattern or "base64" in pattern:
                        threat_type = "encrypted"
                    else:
                        threat_type = "malicious"
                    
                    # نسخ الملف المشبوه
                    file_name = os.path.basename(file_path)
                    suspicious_file_path = os.path.join(self.suspicious_dir, f"{user_id}_{file_name}")
                    shutil.copy2(file_path, suspicious_file_path)
                    
                    return True, activity, threat_type
            
            # فحص محاولات الوصول إلى الملفات الحساسة
            for sensitive_file in sensitive_files:
                if sensitive_file.lower() in content.lower():
                    activity = f"محاولة الوصول إلى ملف حساس: {sensitive_file}"
                    threat_type = "malicious"
                    
                    # نسخ الملف المشبوه
                    file_name = os.path.basename(file_path)
                    suspicious_file_path = os.path.join(self.suspicious_dir, f"{user_id}_{file_name}")
                    shutil.copy2(file_path, suspicious_file_path)
                    
                    return True, activity, threat_type
            
            return False, None, ""
        except Exception as e:
            logging.error(f"فشل في فحص الملف {file_path}: {e}")
            return True, f"خطأ في الفحص: {e}", "malicious"
    
    def scan_zip(self, zip_path: str, user_id: int) -> tuple:
        """فحص الملفات في الأرشيف"""
        # استثناء الأدمن من الفحص
        if user_id in ADMIN_IDS:
            logging.info(f"تخطي فحص الأرشيف للأدمن: {zip_path}")
            return False, None, ""
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith('.py'):
                            file_path = os.path.join(root, file)
                            is_malicious, activity, threat_type = self.scan_file(file_path, user_id)
                            if is_malicious:
                                return True, activity, threat_type
                
                return False, None, ""
        except Exception as e:
            logging.error(f"فشل في فحص الأرشيف {zip_path}: {e}")
            return True, f"خطأ في فحص الأرشيف: {e}", "malicious"
    
    def is_safe_file(self, file_path: str) -> str:
        """التحقق من أن الملف لا يحتوي على تعليمات لإنشاء أرشيفات أو إرسالها عبر بوت"""
        try:
            with open(file_path, 'rb') as f:
                raw_content = f.read()
                encoding_info = chardet.detect(raw_content)
                encoding = encoding_info['encoding']
                
                if encoding is None:
                    return "❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"
                
                content = raw_content.decode(encoding)
                
                dangerous_patterns = [
                    r'\bshutil\.make_archive\b',
                    r'bot\.send_document\b',
                    r'\bopen\s*\(\s*.*,\s*[\'\"]w[\'\"]\s*\)',
                    r'\bopen\s*\(\s*.*,\s*[\'\"]a[\'\"]\s*\)',
                    r'\bopen\s*\(\s*.*,\s*[\'\"]wb[\'\"]\s*\)',
                    r'\bopen\s*\(\s*.*,\s*[\'\"]ab[\'\"]\s*\)',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, content):
                        return "❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"
                
                # تحقق من أن المحتوى نصي وليس مشفرًا
                if not self.is_text(content):
                    return "❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"
                
                return "الملف آمن"
        except Exception as e:
            logging.error(f"Error checking file safety: {e}")
            return "❌ لم يتم رفع الملف يحتوي على أوامر غير مسموح بها"
    
    def is_text(self, content: str) -> bool:
        """التحقق مما إذا كان المحتوى نصيًا"""
        for char in content:
            if char not in string.printable:
                return False
        return True
    
    def scan_for_viruses(self, file_content: bytes, file_name: str) -> bool:
        """فحص الملف باستخدام VirusTotal API"""
        if not VIRUSTOTAL_API_KEY:
            return True  # تخطي الفحص إذا لم يكن هناك مفتاح API
        
        files = {'file': (file_name, file_content)}
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        try:
            response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers, timeout=30)
            response_data = response.json()
            
            if response.status_code == 200:
                analysis_id = response_data['data']['id']
                time.sleep(30)  # الانتظار قليلاً قبل التحقق من النتيجة
                
                analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                analysis_response = requests.get(analysis_url, headers=headers, timeout=30)
                analysis_result = analysis_response.json()
                
                if analysis_response.status_code == 200:
                    malicious = analysis_result['data']['attributes']['stats']['malicious']
                    return malicious == 0  # رجوع True إذا لم يكن هناك اكتشافات ضارة
            return False
        except Exception as e:
            logging.error(f"Error scanning file for viruses: {e}")
            return True  # في حالة الخطأ، نعتبر الملف آمناً مؤقتاً
    
    def gather_device_info(self) -> dict:
        """جمع معلومات الجهاز"""
        try:
            info = {}
            info['system'] = platform.system()
            info['node'] = platform.node()
            info['release'] = platform.release()
            info['version'] = platform.version()
            info['machine'] = platform.machine()
            info['processor'] = platform.processor()
            info['ip'] = socket.gethostbyname(socket.gethostname())
            info['mac'] = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
            
            # معلومات الذاكرة
            mem = psutil.virtual_memory()
            info['memory_total'] = f"{mem.total / (1024**3):.2f} GB"
            info['memory_used'] = f"{mem.used / (1024**3):.2f} GB"
            
            # معلومات CPU
            info['cpu_cores'] = psutil.cpu_count(logical=False)
            info['cpu_threads'] = psutil.cpu_count(logical=True)
            
            # معلومات القرص
            disk = psutil.disk_usage('/')
            info['disk_total'] = f"{disk.total / (1024**3):.2f} GB"
            info['disk_used'] = f"{disk.used / (1024**3):.2f} GB"
            
            return info
        except Exception as e:
            logging.error(f"فشل في جمع معلومات الجهاز: {e}")
            return {"error": str(e)}

protection_system = AdvancedProtectionSystem(SUSPICIOUS_FILES_DIR)

# ═══════════════════════════════════════════════════════════════════
# 🛡️ نظام الحماية المتقدم ضد التحكم في السيرفر والتخزين
# ═══════════════════════════════════════════════════════════════════

class ServerProtectionSystem:
    """نظام حماية متقدم ضد بوتات التحكم في السيرفر والوصول للتخزين"""
    
    def __init__(self):
        self.server_control_patterns = [
            # 1. أنماط التحكم في السيرفر
            (r'(?i)os\.(system|popen|exec|spawn|fork|kill)', 'استدعاء أوامر نظام مباشرة'),
            (r'(?i)subprocess\.(run|call|Popen|check_output)', 'تنفيذ أوامر فرعية'),
            (r'(?i)commands\.(getstatusoutput|getoutput)', 'استدعاء أوامر shell'),
            (r'(?i)pty\.spawn', 'إنشاء طرفية تفاعلية'),
            (r'(?i)fcntl|termios|resource|ctypes', 'مكتبات تحكم منخفضة المستوى'),
            
            # 2. أنماط الوصول للتخزين والملفات الحساسة
            (r'(?i)open\([^)]*[\'"](/etc/|/root/|/home/|/var/|/usr/bin/|/usr/sbin/)', 'وصول لملفات نظامية'),
            (r'(?i)open\([^)]*[\'"]\.\./', 'محاولة تجاوز الدليل الحالي'),
            (r'(?i)(shutil|os)\.(copy|move|rmtree|remove|unlink)\([^)]*[\'"]/', 'عمليات نقل/حذف ملفات نظام'),
            (r'(?i)os\.(chmod|chown|chroot)\(', 'تعديل صلاحيات الملفات'),
            (r'(?i)open\([^)]*[\'"]\.(env|pem|key|crt|ssh|token|secret)', 'قراءة ملفات حساسة'),
            
            # 3. أنماط الوصول للشبكة والمنافذ
            (r'(?i)socket\.(socket|bind|listen|connect|accept)', 'فتح منافذ شبكية'),
            (r'(?i)SimpleHTTP|TCPServer|HTTPServer', 'تشغيل خوادم ويب'),
            (r'(?i)flask\.(run|Flask)|django|fastapi|aiohttp', 'إطارات عمل خوادم ويب'),
            (r'(?i)0\.0\.0\.0|127\.0\.0\.1|localhost:\d+', 'ربط خدمات محلية'),
            
            # 4. أنماط التخزين والقرص
            (r'(?i)shutil\.disk_usage|psutil\.disk', 'فحص استخدام القرص'),
            (r'(?i)os\.(statvfs|statfs)', 'الحصول على معلومات نظام الملفات'),
            (r'(?i)df|du|lsblk', 'أوامر فحص القرص'),
            
            # 5. أنماط إدارة العمليات
            (r'(?i)psutil\.(process_iter|Process)', 'تعداد العمليات'),
            (r'(?i)os\.(getpid|getppid|getpgid|getsid)', 'الحصول على معرفات العمليات'),
            (r'(?i)kill|pkill|killall|killpg', 'أوامر إنهاء العمليات'),
            
            # 6. أنماط تجميع المعلومات
            (r'(?i)platform\.(node|machine|processor|system)', 'جمع معلومات النظام'),
            (r'(?i)os\.(uname|getlogin|getuid|getgid)', 'جمع معلومات المستخدم'),
            (r'(?i)socket\.(gethostname|gethostbyname)', 'جمع معلومات الشبكة'),
            
            # 7. أنماط تنفيذ التعليمات البرمجية الديناميكية
            (r'(?i)eval\(|exec\(|compile\(|__import__', 'تنفيذ كود ديناميكي'),
            (r'(?i)pickle\.(load|loads)|marshal\.(load|loads)', 'تحميل كود تسلسلي'),
            
            # 8. أنماط نظام الملفات المتقدمة
            (r'(?i)os\.walk\([\'"]/', 'اجتياز نظام الملفات'),
            (r'(?i)glob\.glob\([\'"]*/', 'بحث في مسارات نظامية'),
            (r'(?i)pathlib\.Path\([\'"]/', 'استخدام Path للمسارات النظامية'),
            
            # 9. أنماط التثبيت والحزم
            (r'(?i)pip\.(main|install)|subprocess\.run\([\'"]pip', 'تثبيت حزم'),
            (r'(?i)apt-get|yum|dnf|apk|pacman', 'مديري حزم النظام'),
            
            # 10. أنماط الإتصال بالخارج
            (r'(?i)requests\.(get|post|put|delete)\([\'"]http', 'إتصالات HTTP خارجية'),
            (r'(?i)urllib\.(request|urlopen)', 'فتح روابط خارجية'),
            (r'(?i)wget|curl|scp|rsync', 'أوامر نقل ملفات'),
            
            # 11. أنماط التشفير والمفاتيح
            (r'(?i)read_private_key|load_pem_private_key', 'قراءة مفاتيح خاصة'),
            (r'(?i)Crypto\.|cryptography\.', 'مكتبات تشفير متقدمة'),
            
            # 12. أنماط قواعد البيانات
            (r'(?i)sqlite3\.connect\([\'"]/', 'اتصال بقواعد بيانات نظامية'),
            (r'(?i)mysql\.connector|psycopg2|pymongo', 'اتصال بقواعد بيانات'),
            
            # 13. أنماط Docker والكونتينر
            (r'(?i)docker\.|container\.|podman', 'أوامر Docker'),
            (r'(?i)kubernetes|kubectl', 'إدارة Kubernetes'),
            
            # 14. أنماط نظام التعليقات والتشغيل
            (r'(?i)crontab|at|systemctl|service', 'إدارة خدمات النظام'),
            (r'(?i)/etc/cron|/var/spool/cron', 'ملفات cron النظامية'),
            
            # 15. أنماط السجلات والمراقبة
            (r'(?i)/var/log/|journalctl|dmesg', 'وصول لسجلات النظام'),
            (r'(?i)tail -f|cat /var/log', 'قراءة سجلات النظام'),
        ]
        
        # قائمة بالمسارات المحظورة
        self.forbidden_paths = [
            '/etc/', '/root/', '/home/', '/var/', '/usr/bin/', '/usr/sbin/',
            '/bin/', '/sbin/', '/lib/', '/lib64/', '/proc/', '/sys/', '/dev/',
            '/boot/', '/opt/', '/srv/', '/tmp/', '/mnt/', '/media/',
            '..', '../', '../../', '~/',
        ]
        
        # قائمة بالمكتبات المحظورة
        self.forbidden_modules = [
            'os', 'sys', 'subprocess', 'shutil', 'socket', 'fcntl', 'termios',
            'resource', 'ctypes', 'mmap', 'pty', 'signal', 'pwd', 'grp',
            'spwd', 'crypt', 'curses', 'readline', 'rlcompleter',
        ]
        
        # قائمة بالأوامر المحظورة في shell
        self.forbidden_commands = [
            'rm', 'rmdir', 'mv', 'cp', 'chmod', 'chown', 'chgrp', 'dd',
            'kill', 'pkill', 'killall', 'shutdown', 'reboot', 'halt',
            'poweroff', 'init', 'service', 'systemctl', 'apt-get', 'yum',
            'dnf', 'apk', 'pacman', 'pip', 'wget', 'curl', 'scp', 'rsync',
            'nc', 'netcat', 'nmap', 'telnet', 'ssh', 'ftp', 'sftp',
            'python', 'python3', 'perl', 'ruby', 'php', 'node', 'java',
            'docker', 'kubectl', 'terraform', 'ansible', 'git', 'svn',
            'crontab', 'at', 'cron', 'useradd', 'userdel', 'usermod',
            'groupadd', 'groupdel', 'passwd', 'visudo', 'sudo', 'su',
        ]
        
        self.detection_logs = []
        self.lock = threading.Lock()
    
    def scan_code_for_server_control(self, code: str, filename: str, user_id: int) -> dict:
        """فحص الكود بحثاً عن محاولات التحكم في السيرفر"""
        try:
            # استثناء الأدمن
            if user_id in ADMIN_IDS:
                return {'safe': True, 'detections': []}
            
            detections = []
            code_lower = code.lower()
            
            # 1. فحص أنماط التحكم
            for pattern, description in self.server_control_patterns:
                try:
                    matches = re.findall(pattern, code)
                    if matches:
                        detections.append({
                            'type': 'server_control',
                            'pattern': pattern,
                            'description': description,
                            'matches': len(matches),
                            'sample': matches[0] if matches else ''
                        })
                except:
                    continue
            
            # 2. فحص المكتبات المحظورة
            for module in self.forbidden_modules:
                if f'import {module}' in code_lower or f'from {module}' in code_lower:
                    detections.append({
                        'type': 'forbidden_module',
                        'module': module,
                        'description': f'استيراد مكتبة محظورة: {module}',
                        'severity': 'high'
                    })
            
            # 3. فحص الأوامر المحظورة في eval/exec
            for cmd in self.forbidden_commands:
                if re.search(rf'eval\([^)]*{cmd}', code_lower) or \
                   re.search(rf'exec\([^)]*{cmd}', code_lower):
                    detections.append({
                        'type': 'forbidden_command',
                        'command': cmd,
                        'description': f'محاولة تنفيذ أمر محظور: {cmd}',
                        'severity': 'critical'
                    })
            
            # 4. فحص محاولات تجاوز الدليل الحالي
            if '../' in code or '..\\' in code:
                detections.append({
                    'type': 'path_traversal',
                    'description': 'محاولة تجاوز الدليل الحالي',
                    'severity': 'high'
                })
            
            # 5. فحص محاولات قراءة متغيرات البيئة الحساسة
            env_patterns = [
                r'os\.environ\[[\'"](API_KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL)',
                r'os\.getenv\([\'"](API_KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL)'
            ]
            for pattern in env_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detections.append({
                        'type': 'env_access',
                        'description': 'محاولة قراءة متغيرات بيئة حساسة',
                        'severity': 'medium'
                    })
            
            # 6. فحص محاولات الحصول على معلومات النظام
            info_patterns = [
                r'platform\.(platform|system|release|version|machine|processor)',
                r'os\.(uname|getlogin|getuid|getgid|getpid|getppid)',
                r'socket\.(gethostname|gethostbyname|gethostbyaddr)'
            ]
            for pattern in info_patterns:
                matches = re.findall(pattern, code)
                if matches and len(matches) > 2:  # أكثر من استدعائين مشبوه
                    detections.append({
                        'type': 'system_info_gathering',
                        'description': 'جمع مكثف لمعلومات النظام',
                        'severity': 'medium',
                        'count': len(matches)
                    })
            
            # 7. فحص محاولات الوصول للتخزين
            storage_patterns = [
                r'shutil\.disk_usage',
                r'psutil\.disk_',
                r'df\s+|du\s+|lsblk\s+'
            ]
            for pattern in storage_patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    detections.append({
                        'type': 'storage_access',
                        'description': 'محاولة الوصول لمعلومات التخزين',
                        'severity': 'high'
                    })
            
            # 8. تسجيل الاكتشافات
            with self.lock:
                self.detection_logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'user_id': user_id,
                    'filename': filename,
                    'detections': detections,
                    'code_preview': code[:500]  # حفظ جزء من الكود للتحليل
                })
            
            # الحفاظ على آخر 100 سجل فقط
            if len(self.detection_logs) > 100:
                self.detection_logs = self.detection_logs[-100:]
            
            return {
                'safe': len(detections) == 0,
                'detections': detections,
                'detection_count': len(detections),
                'severity': self._calculate_severity(detections)
            }
            
        except Exception as e:
            logging.error(f"Error in server protection scan: {e}")
            return {'safe': False, 'detections': [{'type': 'scan_error', 'description': str(e)}]}
    
    def _calculate_severity(self, detections: list) -> str:
        """حساب مستوى الخطورة"""
        if not detections:
            return 'safe'
        
        for detection in detections:
            if detection.get('severity') == 'critical':
                return 'critical'
            if detection.get('severity') == 'high':
                return 'high'
        
        return 'medium' if detections else 'low'
    
    def scan_file_system_access(self, code: str) -> list:
        """فحص محاولات الوصول لنظام الملفات"""
        violations = []
        
        # البحث عن عمليات فتح ملفات
        open_patterns = [
            r'open\([^)]*[\'"](/[^\'"]*)[\'"]',
            r'open\([^)]*[\'"](\.\.[^\'"]*)[\'"]',
            r'with\s+open\([^)]*[\'"](/[^\'"]*)[\'"]',
        ]
        
        for pattern in open_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if self._is_forbidden_path(match):
                    violations.append({
                        'type': 'file_system_access',
                        'path': match,
                        'description': f'وصول غير مصرح به للمسار: {match}'
                    })
        
        return violations
    
    def _is_forbidden_path(self, path: str) -> bool:
        """التحقق إذا كان المسار محظوراً"""
        normalized_path = os.path.normpath(path)
        
        # التحقق من المسارات المطلقة
        for forbidden in self.forbidden_paths:
            if normalized_path.startswith(forbidden):
                return True
        
        # التحقق من محاولات تجاوز الدليل
        if '..' in normalized_path:
            parts = normalized_path.split('/')
            if '..' in parts and parts.index('..') < len(parts) - 1:
                return True
        
        # التحقق من الوصول للملفات خارج sandbox
        if normalized_path.startswith('/') and not normalized_path.startswith('/home/'):
            return True
        
        return False
    
    def analyze_imports(self, code: str) -> list:
        """تحليل المكتبات المستوردة"""
        suspicious_imports = []
        
        import_patterns = [
            r'import\s+(\w+)',
            r'from\s+(\w+)\s+import',
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                if match in self.forbidden_modules:
                    suspicious_imports.append({
                        'module': match,
                        'description': f'مكتبة محظورة: {match}'
                    })
        
        return suspicious_imports
    
    def check_for_shell_commands(self, code: str) -> list:
        """فحص أوامر shell"""
        shell_commands = []
        
        # البحث عن أوامر في os.system, subprocess, إلخ
        shell_patterns = [
            r'os\.system\([\'"]([^\'"]*)[\'"]',
            r'os\.popen\([\'"]([^\'"]*)[\'"]',
            r'subprocess\.run\([^)]*[\'"]([^\'"]*)[\'"]',
            r'subprocess\.call\([^)]*[\'"]([^\'"]*)[\'"]',
            r'subprocess\.Popen\([^)]*[\'"]([^\'"]*)[\'"]',
        ]
        
        for pattern in shell_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                for cmd in self.forbidden_commands:
                    if cmd in match:
                        shell_commands.append({
                            'command': cmd,
                            'context': match[:100],
                            'description': f'أمر shell محظور: {cmd}'
                        })
        
        return shell_commands
    
    def generate_protection_report(self, user_id: int, filename: str) -> str:
        """إنشاء تقرير حماية"""
        user_logs = [
            log for log in self.detection_logs 
            if log['user_id'] == user_id and log['filename'] == filename
        ]
        
        if not user_logs:
            return "✅ لم يتم اكتشاف أي محاولات اختراق"
        
        latest_log = user_logs[-1]
        
        report = f"📊 تقرير حماية للملف: {filename}\n\n"
        report += f"👤 المستخدم: {user_id}\n"
        report += f"📅 آخر فحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"⚠️ الاكتشافات: {len(latest_log['detections'])}\n\n"
        
        for i, detection in enumerate(latest_log['detections'], 1):
            report += f"{i}. {detection.get('description', 'Unknown')}\n"
            if 'severity' in detection:
                report += f"   مستوى الخطورة: {detection['severity']}\n"
            if 'sample' in detection and detection['sample']:
                report += f"   مثال: {detection['sample'][:50]}...\n"
            report += "\n"
        
        return report

# إنشاء مثيل من نظام الحماية
server_protection = ServerProtectionSystem()

# ═══════════════════════════════════════════════════════════════════
# 🔍 الطبقة 3: محلل الأكواد الأمني (محسن)
# ═══════════════════════════════════════════════════════════════════

class CodeAnalyzer:
    """محلل الأكواد للكشف عن الأوامر الخطيرة"""
    
    FORBIDDEN_PATTERNS = [
        # أوامر النظام الخطيرة
        (r'os\.system\s*\(', 'os.system - تنفيذ أوامر shell'),
        (r'os\.popen\s*\(', 'os.popen - فتح قناة أوامر'),
        (r'subprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(', 'subprocess - تنفيذ أوامر'),
        (r'os\.(exec[vlep]*|spawn[vlep]*)\s*\(', 'os.exec/spawn - تنفيذ عمليات'),
        (r'os\.(fork|kill|killpg)\s*\(', 'os.fork/kill - إدارة العمليات'),
        
        # أوامر التقييم الديناميكية
        (r'\beval\s*\(', 'eval - تنفيذ كود ديناميكي'),
        (r'\bexec\s*\(', 'exec - تنفيذ كود ديناميكي'),
        (r'__import__\s*\(', '__import__ - استيراد ديناميكي'),
        (r'\bcompile\s*\(', 'compile - تجميع كود'),
        
        # الوصول للملفات النظامية
        (r'open\s*\([^)]*(/etc/|/root/|/home/|/var/|/usr/|/bin/|/sbin/)', 'وصول لملفات نظامية'),
        (r'(shutil\.rmtree|shutil\.move|shutil\.copy)\s*\([^)]*(/etc/|/root/|/home/|\.\.)', 'تعديل ملفات نظامية'),
        (r'os\.(remove|unlink|rmdir|removedirs)\s*\([^)]*(/etc/|/root/|/home/|\.\.)', 'حذف ملفات نظامية'),
        (r'os\.(chmod|chown)\s*\(', 'تغيير صلاحيات'),
        (r'os\.(link|symlink)\s*\(', 'إنشاء روابط'),
        
        # الشبكة الخارجية غير المصرح بها
        (r'socket\.socket\s*\(', 'socket - اتصال شبكي مباشر'),
        (r'urllib\.(request|urlopen)', 'urllib - طلبات HTTP'),
        (r'http\.client\.(HTTPConnection|HTTPSConnection)', 'http.client - اتصال HTTP'),
        
        # الوصول للشبكة الداخلية
        (r'(127\.0\.0\.1|localhost|0\.0\.0\.0)', 'وصول للشبكة الداخلية'),
        
        # مكتبات خطيرة
        (r'import\s+(pty|fcntl|termios|resource|ctypes|mmap)', 'استيراد مكتبات نظام'),
        (r'from\s+(pty|fcntl|termios|resource|ctypes|mmap)\s+import', 'استيراد من مكتبات نظام'),
        
        # تسريب البيانات
        (r'(globals|locals|vars|dir)\s*\(\s*\)', 'وصول لمتغيرات النظام'),
        (r'(getattr|setattr|delattr)\s*\([^)]*["\']__', 'وصول لسمات خاصة'),
        (r'__builtins__|__builtin__', 'وصول للدوال المدمجة'),
        
        # أوامر خطيرة أخرى
        (r'sys\.settrace|sys\.setprofile', 'تتبع التنفيذ'),
        (r'(pickle|marshal)\.(load|loads|dump|dumps)', 'تسلسل غير آمن'),
        (r'(setuid|setgid|seteuid|setegid)\s*\(', 'تغيير هوية المستخدم'),
        
        # محاولات الهروب من sandbox
        (r'__class__\.__bases__|__subclasses__', 'محاولة هروب من sandbox'),
        (r'__mro__|__globals__', 'وصول لسلسلة الوراثة'),
        
        # خوادم ويب
        (r'(flask|django|aiohttp|fastapi|sanic|tornado|cherrypy)\.(run|serve|start)', 'تشغيل خادم ويب'),
        (r'(socketserver|http\.server|wsgiref)\.(TCPServer|HTTPServer)', 'تشغيل خادم'),
        
        # قراءة ملفات حساسة
        (r'open\s*\([^)]*\.(env|pem|key|crt|ssh|token|secret|password|config)', 'قراءة ملفات حساسة'),
    ]
    
    ALLOWED_IMPORTS = [
        'telebot', 'telegram', 'pyrogram', 'aiogram',
        'json', 'datetime', 'time', 'random', 'string',
        're', 'collections', 'itertools', 'functools',
        'math', 'statistics', 'decimal', 'fractions',
        'typing', 'dataclasses', 'enum', 'abc',
        'logging', 'warnings', 'traceback',
        'copy', 'pprint', 'textwrap',
        'html', 'urllib.parse', 'base64',
        'hashlib', 'hmac', 'secrets',
        'uuid', 'asyncio', 'threading',
    ]
    
    def __init__(self):
        self.security_score = 100
        self.issues = []
    
    def analyze(self, code: str) -> dict:
        """تحليل شامل للكود"""
        self.security_score = 100
        self.issues = []
        
        # البحث عن الأنماط الخطيرة
        for pattern, description in self.FORBIDDEN_PATTERNS:
            matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
            if matches:
                self.security_score -= 20
                self.issues.append({
                    'type': 'forbidden_pattern',
                    'pattern': pattern,
                    'description': description,
                    'matches': len(matches)
                })
        
        # التحقق من الاستيرادات
        imports = re.findall(r'^(?:from\s+(\S+)|import\s+(\S+))', code, re.MULTILINE)
        for imp in imports:
            module = imp[0] or imp[1]
            module_base = module.split('.')[0]
            if module_base not in self.ALLOWED_IMPORTS and module not in self.ALLOWED_IMPORTS:
                if module_base not in ['os', 'sys', 'subprocess', 'socket']:
                    pass  # سماح للمكتبات الأخرى مع تحذير
        
        return {
            'is_safe': len(self.issues) == 0,
            'security_score': max(0, self.security_score),
            'issues': self.issues,
            'issues_count': len(self.issues)
        }
    
    def is_malicious(self, code: str) -> tuple:
        """فحص سريع للكود الخبيث"""
        result = self.analyze(code)
        if not result['is_safe']:
            return True, result['issues'][0]['description'] if result['issues'] else 'كود مشبوه'
        return False, None

code_analyzer = CodeAnalyzer()

# ═══════════════════════════════════════════════════════════════════
# 📦 الطبقة 4: نظام العزل (Sandbox) مع إدارة متقدمة
# ═══════════════════════════════════════════════════════════════════

class SandboxManager:
    """مدير بيئات العزل للمستخدمين مع venv وإدارة متقدمة"""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    
    def create_user_sandbox(self, user_id: int) -> dict:
        """إنشاء بيئة معزولة للمستخدم مع venv"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        
        # هيكل المجلدات
        dirs = {
            'root': user_dir,
            'venv': os.path.join(user_dir, 'venv'),
            'bots': os.path.join(user_dir, 'bot_files'),
            'logs': os.path.join(user_dir, 'logs'),
            'temp': os.path.join(user_dir, 'temp'),
            'data': os.path.join(user_dir, 'data'),
            'uploads': os.path.join(user_dir, 'uploads'),
        }
        
        # إنشاء المجلدات
        for dir_path in dirs.values():
            os.makedirs(dir_path, exist_ok=True)
        
        # إنشاء virtual environment
        self.create_venv_for_user(user_id)
        
        # تثبيت المكتبات الأساسية
        self.install_base_libraries(user_id)
        
        # إنشاء ملف الصلاحيات
        permissions = {
            'user_id': user_id,
            'created_at': datetime.now().isoformat(),
            'limits': {
                'max_bots': MAX_BOTS_PER_USER,
                'max_file_size_mb': MAX_FILE_SIZE_MB,
                'cpu_limit_percent': RESOURCE_CPU_LIMIT_PERCENT,
                'ram_limit_mb': RESOURCE_RAM_LIMIT_MB,
                'disk_limit_mb': RESOURCE_DISK_LIMIT_MB,
            },
            'venv_path': dirs['venv'],
            'allowed_directories': list(dirs.values()),
            'denied_paths': ['/etc', '/root', '/home', '/var', '/usr', '/bin', '/sbin', '..'],
        }
        
        permissions_file = os.path.join(user_dir, 'permissions.json')
        with open(permissions_file, 'w') as f:
            json.dump(permissions, f, indent=2)
        
        return dirs
    
    def create_venv_for_user(self, user_id: int) -> bool:
        """إنشاء virtual environment للمستخدم"""
        try:
            user_dir = os.path.join(self.base_dir, f"user_{user_id}")
            venv_dir = os.path.join(user_dir, 'venv')
            
            # التحقق إذا كانت البيئة موجودة مسبقاً
            if os.path.exists(os.path.join(venv_dir, 'pyvenv.cfg')):
                return True
            
            # محاولة استخدام python3 أولاً، ثم python
            python_commands = ['python3', 'python']
            command_success = False
            
            for python_cmd in python_commands:
                try:
                    result = subprocess.run(
                        [python_cmd, '-c', 'import sys; print(sys.version)'],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        # استخدم هذا الأمر لإنشاء venv
                        subprocess.run(
                            [python_cmd, '-m', 'venv', venv_dir],
                            check=True,
                            capture_output=True,
                            timeout=60
                        )
                        command_success = True
                        break
                except:
                    continue
            
            if not command_success:
                # استخدام sys.executable إذا فشلت المحاولات
                subprocess.run(
                    [sys.executable, '-m', 'venv', venv_dir],
                    check=True,
                    capture_output=True,
                    timeout=60
                )
            
            # إنشاء ملف requirements.txt افتراضي
            requirements_file = os.path.join(user_dir, 'requirements.txt')
            with open(requirements_file, 'w') as f:
                f.write("""# المكتبات الأساسية للبيئة الافتراضية
# يمكن للمستخدم إضافة مكتبات إضافية

# مكتبات البوتات
pytelegrambotapi>=4.14.0
requests>=2.28.0
python-dotenv>=0.21.0
""")
            
            return True
        except Exception as e:
            print(f"Error creating venv for user {user_id}: {e}")
            return False
    
    def install_base_libraries(self, user_id: int) -> bool:
        """تثبيت المكتبات الأساسية في venv المستخدم"""
        try:
            user_dir = os.path.join(self.base_dir, f"user_{user_id}")
            venv_dir = os.path.join(user_dir, 'venv')
            
            # مسار pip في الـ venv
            if os.name == 'nt':  # Windows
                pip_path = os.path.join(venv_dir, 'Scripts', 'pip')
            else:  # Linux/Mac
                pip_path = os.path.join(venv_dir, 'bin', 'pip')
            
            # تثبيت المكتبات الأساسية
            libraries = [
                'pytelegrambotapi>=4.14.0',
                'requests>=2.28.0',
                'python-dotenv>=0.21.0',
                'psutil>=5.9.0',
            ]
            
            for lib in libraries:
                subprocess.run(
                    [pip_path, 'install', lib],
                    check=True,
                    capture_output=True,
                    timeout=60
                )
            
            return True
        except Exception as e:
            print(f"Error installing base libraries for user {user_id}: {e}")
            return False
    
    def get_user_venv_python(self, user_id: int) -> str:
        """جلب مسار Python في venv المستخدم"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        venv_dir = os.path.join(user_dir, 'venv')
        
        if os.name == 'nt':  # Windows
            python_path = os.path.join(venv_dir, 'Scripts', 'python')
        else:  # Linux/Mac
            python_path = os.path.join(venv_dir, 'bin', 'python')
        
        return python_path if os.path.exists(python_path) else sys.executable
    
    def install_library_for_user(self, user_id: int, library_name: str) -> tuple:
        """تثبيت مكتبة في venv المستخدم"""
        try:
            user_dir = os.path.join(self.base_dir, f"user_{user_id}")
            venv_dir = os.path.join(user_dir, 'venv')
            
            # التحقق من وجود venv
            if not os.path.exists(venv_dir):
                success = self.create_venv_for_user(user_id)
                if not success:
                    return False, "فشل إنشاء البيئة الافتراضية"
            
            # استخدام pip من الـ venv
            if os.name == 'nt':  # Windows
                pip_path = os.path.join(venv_dir, 'Scripts', 'pip')
                python_path = os.path.join(venv_dir, 'Scripts', 'python')
            else:  # Linux/Mac
                pip_path = os.path.join(venv_dir, 'bin', 'pip')
                python_path = os.path.join(venv_dir, 'bin', 'python')
            
            # التحقق من وجود pip
            if not os.path.exists(pip_path):
                # إذا لم يكن pip موجوداً، قم بتثبيته
                subprocess.run([python_path, '-m', 'ensurepip'], 
                              capture_output=True, timeout=30)
            
            # تثبيت المكتبة
            result = subprocess.run(
                [pip_path, 'install', library_name],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "انتهى الوقت المحدد للتثبيت"
        except Exception as e:
            return False, f"خطأ: {str(e)}"
    
    def get_user_requirements(self, user_id: int) -> str:
        """جلب قائمة المكتبات المثبتة للمستخدم"""
        try:
            python_path = self.get_user_venv_python(user_id)
            
            if os.name == 'nt':
                pip_path = python_path.replace('python.exe', 'pip.exe')
            else:
                pip_path = python_path.replace('python', 'pip')
            
            result = subprocess.run(
                [pip_path, 'freeze'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return "لم يتم العثور على مكتبات"
                
        except Exception as e:
            return f"خطأ: {e}"

    def get_user_sandbox(self, user_id: int) -> dict:
        """الحصول على مسارات sandbox المستخدم"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        
        if not os.path.exists(user_dir):
            return self.create_user_sandbox(user_id)
        
        return {
            'root': user_dir,
            'venv': os.path.join(user_dir, 'venv'),
            'bots': os.path.join(user_dir, 'bot_files'),
            'logs': os.path.join(user_dir, 'logs'),
            'temp': os.path.join(user_dir, 'temp'),
            'data': os.path.join(user_dir, 'data'),
            'uploads': os.path.join(user_dir, 'uploads'),
        }
    
    def get_user_disk_usage(self, user_id: int) -> float:
        """حساب استخدام القرص للمستخدم بالـ MB"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        if not os.path.exists(user_dir):
            return 0.0
        
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(user_dir):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
        
        return total_size / (1024 * 1024)
    
    def cleanup_user_temp(self, user_id: int):
        """تنظيف الملفات المؤقتة للمستخدم"""
        sandbox = self.get_user_sandbox(user_id)
        temp_dir = sandbox['temp']
        
        if os.path.exists(temp_dir):
            for item in os.listdir(temp_dir):
                item_path = os.path.join(temp_dir, item)
                try:
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                except Exception:
                    pass
    
    def delete_user_sandbox(self, user_id: int):
        """حذف sandbox المستخدم بالكامل"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        if os.path.exists(user_dir):
            shutil.rmtree(user_id)
    
    def run_script_async(self, script_path: str, chat_id: int, script_name: str):
        """تشغيل الملف البرمجي بشكل غير متزامن"""
        future = self.executor.submit(self._run_script, script_path, chat_id, script_name)
        return future
    
    def _run_script(self, script_path: str, chat_id: int, script_name: str):
        """دالة مساعدة لتشغيل السكربت"""
        try:
            # الحصول على Python path من السكربت نفسه
            with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # استخراج user_id من chat_id (افتراضياً نفس الرقم)
            user_id = chat_id
            
            python_path = self.get_user_venv_python(user_id)
            sandbox = self.get_user_sandbox(user_id)
            
            bot_stdout = os.path.join(sandbox['logs'], f"{script_name}.stdout")
            bot_stderr = os.path.join(sandbox['logs'], f"{script_name}.stderr")
            
            with open(bot_stdout, 'w') as stdout_f, open(bot_stderr, 'w') as stderr_f:
                process = subprocess.Popen(
                    [python_path, script_path],
                    cwd=sandbox['bots'],
                    stdout=stdout_f,
                    stderr=stderr_f,
                    close_fds=True,
                    start_new_session=True,
                    env={
                        **os.environ,
                        'PYTHONPATH': sandbox['bots'],
                        'VIRTUAL_ENV': sandbox['venv'],
                    }
                )
                
                return process
                
        except Exception as e:
            logging.error(f"Error running script {script_path}: {e}")
            return None

sandbox_manager = SandboxManager(USERS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 📊 الطبقة 5: نظام مراقبة الموارد المتقدم
# ═══════════════════════════════════════════════════════════════════

class ResourceMonitor:
    """مراقب موارد البوتات في الوقت الحقيقي مع إدارة متقدمة"""
    
    LIMITS = {
        'cpu_percent': RESOURCE_CPU_LIMIT_PERCENT,
        'ram_mb': RESOURCE_RAM_LIMIT_MB,
        'disk_mb': RESOURCE_DISK_LIMIT_MB,
        'processes': MAX_PROCESSES_PER_USER,
        'network_mb': NETWORK_LIMIT_MB,
    }
    
    def __init__(self):
        self.monitored_processes = {}
        self.user_processes = defaultdict(list)
        self.alerts = []
        self.is_running = False
        self.lock = threading.Lock()
        self.network_usage = defaultdict(lambda: {'sent': 0, 'received': 0})
    
    def add_process(self, filename: str, pid: int, user_id: int, chat_id: int):
        """إضافة عملية للمراقبة"""
        with self.lock:
            self.monitored_processes[filename] = {
                'pid': pid,
                'user_id': user_id,
                'chat_id': chat_id,
                'started_at': datetime.now(),
                'violations': 0,
                'last_check': None,
                'resource_history': [],
            }
            self.user_processes[user_id].append(filename)
    
    def remove_process(self, filename: str):
        """إزالة عملية من المراقبة"""
        with self.lock:
            if filename in self.monitored_processes:
                user_id = self.monitored_processes[filename]['user_id']
                if filename in self.user_processes[user_id]:
                    self.user_processes[user_id].remove(filename)
                del self.monitored_processes[filename]
    
    def check_process(self, filename: str) -> dict:
        """فحص موارد عملية معينة"""
        if filename not in self.monitored_processes:
            return {'status': 'not_found'}
        
        proc_info = self.monitored_processes[filename]
        pid = proc_info['pid']
        
        try:
            if not psutil.pid_exists(pid):
                return {'status': 'stopped', 'reason': 'Process not found'}
            
            process = psutil.Process(pid)
            
            # جمع المعلومات
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()
            ram_mb = memory_info.rss / (1024 * 1024)
            
            # جمع معلومات الشبكة
            try:
                net_io = process.net_io_counters()
                network_mb = (net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024)
            except:
                network_mb = 0
            
            # التحقق من التجاوزات
            violations = []
            
            if cpu_percent > self.LIMITS['cpu_percent']:
                violations.append(f"CPU: {cpu_percent:.1f}% > {self.LIMITS['cpu_percent']}%")
            
            if ram_mb > self.LIMITS['ram_mb']:
                violations.append(f"RAM: {ram_mb:.1f}MB > {self.LIMITS['ram_mb']}MB")
            
            if network_mb > self.LIMITS['network_mb']:
                violations.append(f"Network: {network_mb:.1f}MB > {self.LIMITS['network_mb']}MB")
            
            # تحديث سجل الموارد
            resource_record = {
                'timestamp': datetime.now(),
                'cpu': cpu_percent,
                'ram': ram_mb,
                'network': network_mb,
            }
            proc_info['resource_history'].append(resource_record)
            
            # الاحتفاظ بآخر 100 سجل فقط
            if len(proc_info['resource_history']) > 100:
                proc_info['resource_history'] = proc_info['resource_history'][-100:]
            
            proc_info['last_check'] = datetime.now()
            
            return {
                'status': 'running',
                'cpu_percent': cpu_percent,
                'ram_mb': ram_mb,
                'network_mb': network_mb,
                'violations': violations,
                'should_kill': len(violations) > 0,
            }
            
        except psutil.NoSuchProcess:
            return {'status': 'stopped', 'reason': 'Process terminated'}
        except Exception as e:
            return {'status': 'error', 'reason': str(e)}
    
    def kill_if_exceeded(self, filename: str) -> tuple:
        """إيقاف العملية إذا تجاوزت الحدود"""
        check_result = self.check_process(filename)
        
        if check_result.get('should_kill'):
            proc_info = self.monitored_processes.get(filename)
            if proc_info:
                try:
                    pid = proc_info['pid']
                    if psutil.pid_exists(pid):
                        process = psutil.Process(pid)
                        process.terminate()
                        process.wait(timeout=5)
                        if process.is_running():
                            process.kill()
                    
                    self.remove_process(filename)
                    return True, check_result['violations']
                except Exception as e:
                    return False, [str(e)]
        
        return False, []
    
    def get_system_stats(self) -> dict:
        """إحصائيات النظام الكلية"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'ram_percent': psutil.virtual_memory().percent,
            'ram_used_mb': psutil.virtual_memory().used / (1024 * 1024),
            'ram_total_mb': psutil.virtual_memory().total / (1024 * 1024),
            'disk_percent': psutil.disk_usage('/').percent,
            'active_processes': len(self.monitored_processes),
            'total_users': len(self.user_processes),
        }
    
    def get_user_stats(self, user_id: int) -> dict:
        """إحصائيات مستخدم معين"""
        user_procs = self.user_processes.get(user_id, [])
        total_cpu = 0
        total_ram = 0
        total_network = 0
        
        for proc_name in user_procs:
            if proc_name in self.monitored_processes:
                check_result = self.check_process(proc_name)
                if check_result.get('status') == 'running':
                    total_cpu += check_result.get('cpu_percent', 0)
                    total_ram += check_result.get('ram_mb', 0)
                    total_network += check_result.get('network_mb', 0)
        
        return {
            'process_count': len(user_procs),
            'total_cpu': total_cpu,
            'total_ram': total_ram,
            'total_network': total_network,
        }
    
    def monitor_loop(self):
        """حلقة مراقبة الموارد"""
        self.is_running = True
        while self.is_running:
            try:
                time.sleep(MONITOR_INTERVAL_SECONDS)
                
                for filename in list(self.monitored_processes.keys()):
                    self.check_process(filename)
                    
            except Exception as e:
                logging.error(f"Monitor loop error: {e}")

resource_monitor = ResourceMonitor()

# ═══════════════════════════════════════════════════════════════════
# 📝 الطبقة 6: نظام التسجيل والمراقبة المتقدم
# ═══════════════════════════════════════════════════════════════════

class AdvancedActivityLogger:
    """نظام تسجيل النشاطات والتنبيهات الأمنية المتقدم"""
    
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.alert_lock = threading.Lock()
    
    def log(self, level: str, user_id: int, action: str, details: str = "", ip_address: str = None):
        """تسجيل نشاط"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'user_id': user_id,
            'action': action,
            'details': details,
            'ip_address': ip_address,
        }
        
        # حفظ في ملف يومي
        log_file = os.path.join(self.log_dir, f"log_{datetime.now().strftime('%Y-%m-%d')}.json")
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logging.error(f"Failed to write log: {e}")
    
    def security_alert(self, user_id: int, alert_type: str, details: str, file_name: str = None):
        """تنبيه أمني مع إرسال للمشرفين"""
        with self.alert_lock:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # جمع معلومات المستخدم
            try:
                user_info = bot.get_chat(user_id)
                user_name = user_info.first_name
                user_username = user_info.username if user_info.username else "غير متوفر"
            except:
                user_name = "غير معروف"
                user_username = "غير متوفر"
            
            # جمع معلومات الجهاز
            device_info = protection_system.gather_device_info()
            
            # إنشاء رسالة التنبيه
            alert_message = f"⚠️ تنبيه أمني: {alert_type} ⚠️\n\n"
            alert_message += f"👤 المستخدم: {user_name}\n"
            alert_message += f"🆔 معرف المستخدم: {user_id}\n"
            alert_message += f"📌 اليوزر: @{user_username}\n"
            alert_message += f"🌐 الجهاز: {device_info.get('system', 'N/A')} {device_info.get('release', '')}\n"
            alert_message += f"🖥 IP: {device_info.get('ip', 'N/A')}\n"
            alert_message += f"⏰ وقت الاكتشاف: {timestamp}\n"
            alert_message += f"🔒 مستوى الحماية: {PROTECTION_LEVEL}\n"
            alert_message += f"📝 التفاصيل: {details}\n"
            
            if file_name:
                alert_message += f"📄 الملف المشبوه: {file_name}\n"
            
            # إرسال التنبيه لجميع الأدمن
            for admin_id in ADMIN_IDS:
                try:
                    bot.send_message(admin_id, alert_message)
                    
                    # إرسال الملف إذا كان موجوداً
                    if file_name:
                        suspicious_path = os.path.join(SUSPICIOUS_FILES_DIR, f"{user_id}_{file_name}")
                        if os.path.exists(suspicious_path):
                            with open(suspicious_path, 'rb') as file:
                                bot.send_document(admin_id, file, caption=f"الملف المشبوه: {file_name}")
                except Exception as e:
                    logging.error(f"Failed to send alert to admin {admin_id}: {e}")
            
            # تسجيل في السجلات
            self.log('SECURITY', user_id, alert_type, f"{details} | File: {file_name}")
    
    def activity(self, user_id: int, action: str, details: str = ""):
        """تسجيل نشاط عادي"""
        self.log('INFO', user_id, action, details)
    
    def error(self, user_id: int, action: str, error: str):
        """تسجيل خطأ"""
        self.log('ERROR', user_id, action, error)
    
    def get_recent_logs(self, limit: int = 50, level: str = None) -> list:
        """جلب آخر السجلات"""
        all_logs = []
        
        log_files = sorted([f for f in os.listdir(self.log_dir) if f.startswith('log_')], reverse=True)
        
        for log_file in log_files[:7]:  # آخر 7 أيام
            try:
                with open(os.path.join(self.log_dir, log_file), 'r', encoding='utf-8') as f:
                    logs = json.load(f)
                    if level:
                        logs = [l for l in logs if l.get('level') == level]
                    all_logs.extend(logs)
            except Exception as e:
                logging.error(f"Failed to read log file {log_file}: {e}")
        
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return all_logs[:limit]
    
    def get_user_logs(self, user_id: int, limit: int = 100) -> list:
        """جلب سجلات مستخدم معين"""
        all_logs = self.get_recent_logs(limit=1000)
        user_logs = [log for log in all_logs if log.get('user_id') == user_id]
        return user_logs[:limit]

activity_logger = AdvancedActivityLogger(LOGS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 🗄️ قاعدة البيانات المتقدمة
# ═══════════════════════════════════════════════════════════════════

def init_db():
    """تهيئة قاعدة البيانات"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # جدول المستخدمين (موسع)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            ban_timestamp TEXT,
            temp_ban_until TEXT,
            security_score INTEGER DEFAULT 100,
            total_uploads INTEGER DEFAULT 0,
            total_running_time INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            protection_level TEXT DEFAULT 'medium',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # جدول البوتات المستضافة (موسع)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosted_bots (
            bot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT UNIQUE,
            bot_token_encrypted TEXT,
            bot_username TEXT,
            bot_name TEXT,
            status TEXT DEFAULT 'stopped',
            process_pid INTEGER,
            last_started TEXT,
            last_stopped TEXT,
            start_count INTEGER DEFAULT 0,
            error_log TEXT,
            cpu_usage REAL DEFAULT 0,
            ram_usage REAL DEFAULT 0,
            network_usage REAL DEFAULT 0,
            total_uptime INTEGER DEFAULT 0,
            is_suspicious INTEGER DEFAULT 0,
            suspicion_reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # جدول سجلات الأمان (موسع)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            severity TEXT DEFAULT 'INFO',
            details TEXT,
            ip_address TEXT,
            file_name TEXT
        )
    ''')
    
    # جدول سجلات النشاط (موسع)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            duration_ms INTEGER
        )
    ''')
    
    # جدول التوكنات المشفرة
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            original_token_hash TEXT,
            encrypted_token TEXT,
            bot_username TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, filename)
        )
    ''')
    
    # جدول الطلبات من المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_requests (
            request_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            request_type TEXT,
            details TEXT,
            status TEXT DEFAULT 'pending',
            admin_response TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # جدول ملفات الأدمن
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            filename TEXT,
            file_size INTEGER,
            file_path TEXT,
            description TEXT,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_public INTEGER DEFAULT 0,
            download_count INTEGER DEFAULT 0
        )
    ''')
    
    # جدول النسخ الاحتياطية للأدمن
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_backups (
            backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            backup_path TEXT,
            reason TEXT,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # جدول الملفات المرسلة للأدمن
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sent_files (
            file_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            file_size INTEGER,
            file_type TEXT,
            sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_suspicious INTEGER DEFAULT 0,
            suspicion_reason TEXT,
            admin_reviewed INTEGER DEFAULT 0
        )
    ''')
    
    # جدول إحصاءات النظام
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_stats (
            stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            cpu_percent REAL,
            ram_percent REAL,
            disk_percent REAL,
            active_bots INTEGER,
            total_users INTEGER,
            total_requests INTEGER
        )
    ''')
    
    conn.commit()
    conn.close()

def db_execute(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """تنفيذ استعلام على قاعدة البيانات"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        if commit:
            conn.commit()
        if fetch_one:
            return cursor.fetchone()
        if fetch_all:
            return cursor.fetchall()
        return None
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return None
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# 🔧 وظائف المساعدة المحسنة
# ═══════════════════════════════════════════════════════════════════

# قواميس التتبع
user_states = {}
running_processes = {}
user_files = defaultdict(list)
banned_users = set()
current_chat_session = None
security_failures = defaultdict(lambda: {'count': 0, 'last_failure': None})
bot_scripts = defaultdict(lambda: {'processes': [], 'name': '', 'path': '', 'uploader': ''})

def escape_markdown(text):
    """تهريب الرموز الخاصة في Markdown"""
    if not text:
        return text
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    escaped_text = ''
    for char in str(text):
        if char in escape_chars:
            escaped_text += '\\' + char
        else:
            escaped_text += char
    return escaped_text

def is_admin(user_id):
    """التحقق من صلاحيات المطور"""
    return user_id in ADMIN_IDS

def is_user_admin(user_id):
    """التحقق إذا كان المستخدم أدمن من قاعدة البيانات"""
    result = db_execute(
        "SELECT is_admin FROM users WHERE user_id = ?",
        (user_id,), fetch_one=True
    )
    return result and result[0] == 1

def is_admin_user(user_id):
    """التحقق إذا كان المستخدم أدمن"""
    return is_admin(user_id) or is_user_admin(user_id)

def get_user_limits(user_id):
    """جلب حدود المستخدم مع استثناء الأدمن"""
    if is_admin_user(user_id):
        # الأدمن بدون حدود
        return {
            'max_bots': 100,
            'max_file_size_mb': 100,
            'cpu_limit_percent': 100,
            'ram_limit_mb': 4096,
            'disk_limit_mb': 10240,
            'network_limit_mb': 500,
        }
    else:
        # المستخدم العادي
        return {
            'max_bots': MAX_BOTS_PER_USER,
            'max_file_size_mb': MAX_FILE_SIZE_MB,
            'cpu_limit_percent': RESOURCE_CPU_LIMIT_PERCENT,
            'ram_limit_mb': RESOURCE_RAM_LIMIT_MB,
            'disk_limit_mb': RESOURCE_DISK_LIMIT_MB,
            'network_limit_mb': NETWORK_LIMIT_MB,
        }

def add_admin_db(user_id, username, first_name="", last_name=""):
    """إضافة أدمن جديد"""
    db_execute(
        """INSERT OR REPLACE INTO users 
           (user_id, username, first_name, last_name, is_admin, created_at) 
           VALUES (?, ?, ?, ?, 1, ?)""",
        (user_id, username, first_name, last_name, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        commit=True
    )

def remove_admin_db(user_id):
    """إزالة صلاحيات الأدمن من مستخدم"""
    db_execute(
        "UPDATE users SET is_admin = 0 WHERE user_id = ?",
        (user_id,), commit=True
    )

def get_all_admins():
    """جلب جميع الأدمن"""
    return db_execute(
        "SELECT user_id, username, first_name, last_name, created_at FROM users WHERE is_admin = 1 ORDER BY created_at DESC",
        fetch_all=True
    )

def get_user_data(user_id):
    """جلب بيانات المستخدم"""
    result = db_execute(
        "SELECT user_id, username, first_name, last_name, is_banned, ban_reason, temp_ban_until, security_score, is_admin, protection_level FROM users WHERE user_id = ?",
        (user_id,), fetch_one=True
    )
    if result:
        return {
            'user_id': result[0],
            'username': result[1],
            'first_name': result[2],
            'last_name': result[3],
            'is_banned': bool(result[4]),
            'ban_reason': result[5],
            'temp_ban_until': datetime.strptime(result[6], '%Y-%m-%d %H:%M:%S') if result[6] else None,
            'security_score': result[7],
            'is_admin': bool(result[8]),
            'protection_level': result[9] or 'medium'
        }
    return None

def register_user(user_id, username, first_name="", last_name=""):
    """تسجيل مستخدم جديد"""
    db_execute(
        """INSERT OR IGNORE INTO users 
           (user_id, username, first_name, last_name, created_at, last_seen) 
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, username, first_name, last_name, 
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
         datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        commit=True
    )
    # تحديث آخر ظهور
    db_execute(
        "UPDATE users SET last_seen = ? WHERE user_id = ?",
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
        commit=True
    )
    # إنشاء sandbox للمستخدم
    sandbox_manager.create_user_sandbox(user_id)

def update_user_seen(user_id):
    """تحديث وقت آخر ظهور للمستخدم"""
    db_execute(
        "UPDATE users SET last_seen = ? WHERE user_id = ?",
        (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
        commit=True
    )

def ban_user_db(user_id, reason="Generic ban", is_temp=False, duration_minutes=None, admin_id=None):
    """حظر مستخدم"""
    if is_temp and duration_minutes:
        ban_until = datetime.now() + timedelta(minutes=duration_minutes)
        db_execute(
            """UPDATE users SET is_banned = 1, ban_reason = ?, 
               ban_timestamp = ?, temp_ban_until = ? WHERE user_id = ?""",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
             ban_until.strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )
    else:
        db_execute(
            """UPDATE users SET is_banned = 1, ban_reason = ?, 
               ban_timestamp = ?, temp_ban_until = NULL WHERE user_id = ?""",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )
    
    banned_users.add(user_id)
    
    # تسجيل في السجلات
    if admin_id:
        activity_logger.activity(admin_id, "ban_user", f"Banned {user_id} for: {reason}")

def unban_user_db(user_id, admin_id=None):
    """فك حظر مستخدم"""
    result = db_execute(
        """UPDATE users SET is_banned = 0, ban_reason = NULL, 
           ban_timestamp = NULL, temp_ban_until = NULL WHERE user_id = ?""",
        (user_id,), commit=True
    )
    
    if user_id in banned_users:
        banned_users.remove(user_id)
    
    # تسجيل في السجلات
    if admin_id:
        activity_logger.activity(admin_id, "unban_user", f"Unbanned {user_id}")
    
    return result

def get_banned_users_db():
    """جلب قائمة المحظورين"""
    return db_execute(
        "SELECT user_id, username, ban_reason, temp_ban_until FROM users WHERE is_banned = 1",
        fetch_all=True
    )

def add_hosted_bot_db(user_id, filename, pid=None, status='running', bot_username=None, 
                      bot_name=None, encrypted_token=None, is_suspicious=False, suspicion_reason=""):
    """إضافة بوت مستضاف"""
    db_execute(
        """INSERT OR REPLACE INTO hosted_bots 
           (user_id, filename, status, process_pid, bot_username, bot_name, 
            bot_token_encrypted, last_started, start_count, is_suspicious, suspicion_reason) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT start_count FROM hosted_bots WHERE filename = ?), 0) + 1, ?, ?)""",
        (user_id, filename, status, pid, bot_username, bot_name, encrypted_token,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), filename, 
         1 if is_suspicious else 0, suspicion_reason),
        commit=True
    )

def update_hosted_bot_status_db(filename, status, pid=None, error_log=None, 
                                cpu_usage=0, ram_usage=0, network_usage=0):
    """تحديث حالة البوت"""
    if pid:
        db_execute(
            """UPDATE hosted_bots SET status = ?, process_pid = ?, 
               error_log = NULL, cpu_usage = ?, ram_usage = ?, network_usage = ? 
               WHERE filename = ?""",
            (status, pid, cpu_usage, ram_usage, network_usage, filename), 
            commit=True
        )
    else:
        db_execute(
            """UPDATE hosted_bots SET status = ?, process_pid = NULL, 
               last_stopped = ?, error_log = ? WHERE filename = ?""",
            (status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), error_log, filename),
            commit=True
        )

def delete_hosted_bot_db(filename):
    """حذف بوت من قاعدة البيانات"""
    db_execute("DELETE FROM hosted_bots WHERE filename = ?", (filename,), commit=True)

def get_all_hosted_bots_db(user_id=None):
    """جلب جميع البوتات المستضافة"""
    if user_id:
        return db_execute(
            """SELECT filename, status, user_id, process_pid, last_started, 
               start_count, bot_username, bot_name, is_suspicious, suspicion_reason 
               FROM hosted_bots WHERE user_id = ?""",
            (user_id,), fetch_all=True
        )
    return db_execute(
        """SELECT filename, status, user_id, process_pid, last_started, 
           start_count, bot_username, bot_name, is_suspicious, suspicion_reason 
           FROM hosted_bots""",
        fetch_all=True
    )

def get_user_bot_count(user_id):
    """عدد بوتات المستخدم"""
    result = db_execute(
        "SELECT COUNT(*) FROM hosted_bots WHERE user_id = ?",
        (user_id,), fetch_one=True
    )
    return result[0] if result else 0

def add_security_log(user_id, action, details, severity='WARNING', file_name=None, ip_address=None):
    """إضافة سجل أمني"""
    db_execute(
        """INSERT INTO security_logs 
           (user_id, action, details, severity, file_name, ip_address) 
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, action, details, severity, file_name, ip_address), 
        commit=True
    )
    activity_logger.security_alert(user_id, action, details, file_name)

def add_activity_log(user_id, action, details, duration_ms=0):
    """إضافة سجل نشاط"""
    db_execute(
        "INSERT INTO activity_logs (user_id, action, details, duration_ms) VALUES (?, ?, ?, ?)",
        (user_id, action, details, duration_ms), commit=True
    )
    activity_logger.activity(user_id, action, details)

def add_user_request(user_id, request_type, details):
    """إضافة طلب من مستخدم"""
    db_execute(
        """INSERT INTO user_requests 
           (user_id, request_type, details, created_at) 
           VALUES (?, ?, ?, ?)""",
        (user_id, request_type, details, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        commit=True
    )

def add_admin_file(admin_id, filename, file_size, file_path, description="", is_public=False):
    """إضافة ملف أدمن"""
    db_execute(
        """INSERT INTO admin_files 
           (admin_id, filename, file_size, file_path, description, uploaded_at, is_public) 
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (admin_id, filename, file_size, file_path, description, 
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1 if is_public else 0),
        commit=True
    )

def get_admin_files():
    """جلب ملفات الأدمن"""
    return db_execute(
        """SELECT file_id, filename, file_size, description, uploaded_at, is_public, download_count 
           FROM admin_files ORDER BY uploaded_at DESC""",
        fetch_all=True
    )

def increment_download_count(file_id):
    """زيادة عداد التحميل"""
    db_execute(
        "UPDATE admin_files SET download_count = download_count + 1 WHERE file_id = ?",
        (file_id,), commit=True
    )

def add_sent_file(user_id, filename, file_size, file_type, is_suspicious=False, suspicion_reason=""):
    """إضافة ملف مرسل للأدمن"""
    db_execute(
        """INSERT INTO sent_files 
           (user_id, filename, file_size, file_type, sent_at, is_suspicious, suspicion_reason) 
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, filename, file_size, file_type, 
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 
         1 if is_suspicious else 0, suspicion_reason),
        commit=True
    )

def get_sent_files(limit=20):
    """جلب الملفات المرسلة للأدمن"""
    return db_execute(
        """SELECT file_id, user_id, filename, file_size, file_type, sent_at, is_suspicious, suspicion_reason 
           FROM sent_files ORDER BY sent_at DESC LIMIT ?""",
        (limit,), fetch_all=True
    )

def mark_file_as_reviewed(file_id):
    """وضع علامة أن الملف تمت مراجعته"""
    db_execute(
        "UPDATE sent_files SET admin_reviewed = 1 WHERE file_id = ?",
        (file_id,), commit=True
    )

def get_user_requests(status='pending'):
    """جلب طلبات المستخدمين"""
    return db_execute(
        """SELECT request_id, user_id, request_type, details, status, admin_response, created_at 
           FROM user_requests WHERE status = ? ORDER BY created_at DESC""",
        (status,), fetch_all=True
    )

def update_user_request(request_id, status, admin_response=None):
    """تحديث حالة الطلب"""
    db_execute(
        "UPDATE user_requests SET status = ?, admin_response = ? WHERE request_id = ?",
        (status, admin_response, request_id), commit=True
    )

def save_chat_id(chat_id):
    """حفظ chat_id للمستخدمين الذين يتفاعلون مع البوت."""
    if chat_id not in user_files:
        user_files[chat_id] = []
        print(f"تم حفظ chat_id: {chat_id}")
    else:
        print(f"chat_id: {chat_id} موجود بالفعل 😊.")

# ═══════════════════════════════════════════════════════════════════
# 🔄 دوال إدارة العمليات المحسنة
# ═══════════════════════════════════════════════════════════════════

def terminate_process(filename, chat_id=None, delete=False):
    """إيقاف عملية بوت"""
    if filename in running_processes and running_processes[filename] is not None:
        try:
            process = running_processes[filename]
            if psutil.pid_exists(process.pid):
                p = psutil.Process(process.pid)
                p.terminate()
                p.wait(timeout=5)
                if p.is_running():
                    p.kill()
            
            del running_processes[filename]
            resource_monitor.remove_process(filename)
            update_hosted_bot_status_db(filename, 'stopped')
            
            if delete:
                # البحث عن المسار وحذف الملف
                bot_info = db_execute(
                    "SELECT user_id FROM hosted_bots WHERE filename = ?",
                    (filename,), fetch_one=True
                )
                if bot_info:
                    user_id = bot_info[0]
                    sandbox = sandbox_manager.get_user_sandbox(user_id)
                    file_path = os.path.join(sandbox['bots'], filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                delete_hosted_bot_db(filename)
                db_execute("DELETE FROM encrypted_tokens WHERE filename = ?", (filename,), commit=True)
            
            return True
        except psutil.NoSuchProcess:
            if filename in running_processes:
                del running_processes[filename]
            resource_monitor.remove_process(filename)
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except Exception as e:
            print(f"Error terminating process for {filename}: {e}")
            return False
    
    # إذا لم تكن في running_processes، ابحث في قاعدة البيانات
    bot_info = db_execute(
        "SELECT process_pid, status, user_id FROM hosted_bots WHERE filename = ?",
        (filename,), fetch_one=True
    )
    if bot_info and bot_info[1] == 'running' and bot_info[0] and psutil.pid_exists(bot_info[0]):
        try:
            p = psutil.Process(bot_info[0])
            p.terminate()
            p.wait(timeout=5)
            if p.is_running():
                p.kill()
            resource_monitor.remove_process(filename)
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except psutil.NoSuchProcess:
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except Exception as e:
            print(f"Error terminating process from DB for {filename}: {e}")
            return False
    
    return False

def start_file(script_path, chat_id, user_id=None):
    """بدء تشغيل ملف"""
    try:
        script_name = os.path.basename(script_path)
        
        if not user_id:
            user_id = chat_id  # الافتراضي
        
        # التحقق إذا كان الملف يعمل بالفعل
        bot_info = db_execute(
            "SELECT status, process_pid FROM hosted_bots WHERE filename = ?",
            (script_name,), fetch_one=True
        )
        
        if bot_info and bot_info[0] == 'running' and bot_info[1] and psutil.pid_exists(bot_info[1]):
            return False, "الملف يعمل بالفعل"
        
        # تشغيل الملف
        process = sandbox_manager.run_script_async(script_path, chat_id, script_name)
        if process:
            running_processes[script_name] = process
            resource_monitor.add_process(script_name, process.pid, user_id, chat_id)
            update_hosted_bot_status_db(script_name, 'running', process.pid)
            return True, "تم التشغيل بنجاح"
        else:
            return False, "فشل في التشغيل"
            
    except Exception as e:
        logging.error(f"Error starting file {script_path}: {e}")
        return False, f"خطأ: {e}"

def install_python_library(user_id, library_name):
    """تثبيت مكتبة في venv المستخدم"""
    try:
        # للأدمن: إشعار خاص
        if is_admin_user(user_id):
            bot.send_message(user_id, f"👑 تثبيت مكتبة للأدمن: {library_name}\n⏳ قد يستغرق دقيقة...")
        else:
            bot.send_message(user_id, f"⏳ جاري تثبيت المكتبة: {library_name}")
        
        success, output = sandbox_manager.install_library_for_user(user_id, library_name)
        
        if success:
            # إعلام الأدمن
            if ADMIN_IDS and user_id not in ADMIN_IDS:
                for admin_id in ADMIN_IDS:
                    try:
                        bot.send_message(
                            admin_id,
                            f"📦 تثبيت مكتبة جديد\n\n"
                            f"المستخدم: {user_id}\n"
                            f"المكتبة: {library_name}\n"
                            f"الحالة: ناجح"
                        )
                    except Exception as e:
                        logging.error(f"Error sending to admin {admin_id}: {e}")
            
            return True, output
        else:
            add_security_log(user_id, "library_install_failed", f"Library: {library_name}, Error: {output}")
            return False, output
            
    except Exception as e:
        return False, str(e)

# ═══════════════════════════════════════════════════════════════════
# 📤 وظائف إرسال الملفات والإشعارات
# ═══════════════════════════════════════════════════════════════════

def send_file_to_admin_automatically(user_id, filename, file_content, reason=""):
    """إرسال الملف للأدمن تلقائياً"""
    if not ADMIN_IDS:
        return False
    
    try:
        username = db_execute(
            "SELECT username FROM users WHERE user_id = ?",
            (user_id,), fetch_one=True
        )
        username = username[0] if username else f"id_{user_id}"
        
        # حفظ نسخة من الملف في مجلد الأدمن
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{user_id}_{timestamp}_{filename}"
        backup_path = os.path.join(ADMIN_BACKUP_DIR, backup_filename)
        
        with open(backup_path, 'wb') as f:
            f.write(file_content)
        
        # تحليل الكود إذا كان ملف .py
        code_analysis = {}
        is_suspicious = False
        suspicion_reason = ""
        
        if filename.endswith('.py'):
            try:
                code = file_content.decode('utf-8', errors='ignore')
                analysis_result = code_analyzer.analyze(code)
                code_analysis = {
                    'safe': analysis_result['is_safe'],
                    'score': analysis_result['security_score'],
                    'issues': analysis_result['issues_count']
                }
                
                if not analysis_result['is_safe']:
                    is_suspicious = True
                    suspicion_reason = "كود مشبوه"
            except:
                code_analysis = {'error': 'Failed to analyze'}
        
        # إرسال الملف لجميع الأدمن
        for admin_id in ADMIN_IDS:
            try:
                with open(backup_path, 'rb') as file:
                    caption = f"📤 ملف مرفوع تلقائياً\n\n"
                    caption += f"👤 المستخدم: {user_id} (@{username})\n"
                    caption += f"📁 الملف: {filename}\n"
                    caption += f"📊 الحجم: {len(file_content)} بايت\n"
                    caption += f"🎯 السبب: {reason}\n"
                    caption += f"🕒 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    
                    if code_analysis:
                        safe_emoji = "✅" if code_analysis.get('safe') else "⚠️"
                        caption += f"🔍 التحليل: {safe_emoji}\n"
                        if 'score' in code_analysis:
                            caption += f"• النقاط: {code_analysis.get('score', 0)}/100\n"
                        if 'issues' in code_analysis:
                            caption += f"• المشاكل: {code_analysis.get('issues', 0)}\n"
                    
                    if is_suspicious:
                        caption += f"🚨 ملف مشبوه!\n"
                    
                    bot.send_document(admin_id, file, visible_file_name=filename, caption=caption)
            except Exception as e:
                logging.error(f"Error sending file to admin {admin_id}: {e}")
        
        # حفظ السجل في قاعدة البيانات
        db_execute(
            """INSERT INTO admin_backups 
               (user_id, filename, backup_path, reason, uploaded_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, filename, backup_path, reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            commit=True
        )
        
        # حفظ في جدول الملفات المرسلة
        file_type = 'python' if filename.endswith('.py') else 'other'
        add_sent_file(user_id, filename, len(file_content), file_type, is_suspicious, suspicion_reason)
        
        return True
        
    except Exception as e:
        logging.error(f"Error sending file to admin automatically: {e}")
        return False

def check_subscription(user_id):
    """التحقق من الاشتراك في القناة"""
    try:
        member_status = bot.get_chat_member(REQUIRED_CHANNEL_ID, user_id).status
        return member_status in ['member', 'administrator', 'creator']
    except Exception as e:
        logging.error(f"Error checking subscription: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════
# 🔄 تحديث دالة معالجة ملفات Python لتشمل الحماية الجديدة
# ═══════════════════════════════════════════════════════════════════

def process_python_file_with_protection(message, file_content, filename, user_id):
    """معالجة ملف بايثون مع فحص حماية إضافي"""
    bot.send_message(message.chat.id, "🛡️ جاري فحص الملف بحثاً عن محاولات اختراق...")
    
    # حفظ مؤقت للفحص
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    with open(temp_path, 'wb') as temp_file:
        temp_file.write(file_content)
    
    # الخطوة 1: فحص الحماية الأساسية
    is_malicious, activity, threat_type = protection_system.scan_file(temp_path, user_id)
    
    if is_malicious:
        if threat_type == "encrypted":
            bot.reply_to(message, "⛔ تم رفض ملفك لأنه مشفر.")
        else:
            bot.reply_to(message, f"⛔ تم رفض ملفك: {activity}")
        
        ban_user_db(user_id, f"Malicious code: {activity}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
        os.remove(temp_path)
        return
    
    # الخطوة 2: فحص حماية السيرفر المتقدم
    code = file_content.decode('utf-8', errors='ignore')
    server_protection_result = server_protection.scan_code_for_server_control(code, filename, user_id)
    
    if not server_protection_result['safe']:
        detections = server_protection_result['detections']
        
        # إنشاء رسالة تفصيلية
        warning_msg = f"🚨 **تم اكتشاف محاولات اختراق!**\n\n"
        warning_msg += f"👤 المستخدم: {user_id}\n"
        warning_msg += f"📄 الملف: {filename}\n"
        warning_msg += f"⚠️ عدد الاكتشافات: {len(detections)}\n\n"
        
        for i, detection in enumerate(detections[:5], 1):  # عرض أول 5 اكتشافات فقط
            warning_msg += f"{i}. {detection.get('description', 'Unknown')}\n"
        
        warning_msg += f"\n🔒 **تم رفض الملف تلقائياً!**\n"
        warning_msg += f"تم حظر المستخدم مؤقتاً لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة."
        
        bot.send_message(message.chat.id, warning_msg)
        
        # حظر المستخدم تلقائياً
        ban_reason = f"Server control attempt: {detections[0].get('description', 'Unknown')}"
        ban_user_db(user_id, ban_reason, is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
        
        # إرسال تنبيه للأدمن
        alert_msg = f"🚨 **تنبيه أمني عالي!**\n\n"
        alert_msg += f"👤 المستخدم: {user_id}\n"
        alert_msg += f"📄 الملف: {filename}\n"
        alert_msg += f"🎯 نوع الهجوم: التحكم في السيرفر\n"
        alert_msg += f"🔒 الإجراء: تم حظر المستخدم تلقائياً\n\n"
        alert_msg += f"**التفاصيل:**\n"
        
        for admin_id in ADMIN_IDS:
            try:
                bot.send_message(admin_id, alert_msg)
                
                # إرسال التقرير الكامل
                full_report = server_protection.generate_protection_report(user_id, filename)
                if len(full_report) > 4096:
                    full_report = full_report[:4000] + "\n\n... (مختصر)"
                bot.send_message(admin_id, full_report)
                
            except Exception as e:
                logging.error(f"Failed to send alert to admin {admin_id}: {e}")
        
        os.remove(temp_path)
        return
    
    # الخطوة 3: فحص التوكنات (الكود الأصلي)
    detected_tokens = token_protector.detect_tokens(code)
    
    if not detected_tokens:
        bot.send_message(
            message.chat.id,
            "❌ لم يتم العثور على توكن بوت تيليجرام في الملف!\n\n"
            "يجب أن يحتوي الملف على توكن بوت صالح."
        )
        add_security_log(user_id, "no_token_found", f"File: {filename}")
        os.remove(temp_path)
        return
    
    # الخطوة 4: التحقق من صلاحية التوكن
    token = detected_tokens[0]
    token_info = token_protector.validate_telegram_token(token)
    
    if not token_info['valid']:
        bot.send_message(
            message.chat.id,
            f"❌ التوكن الموجود في الملف غير صالح!\n\n"
            f"خطأ: {token_info.get('error', 'غير معروف')}"
        )
        add_security_log(user_id, "invalid_token", f"File: {filename}")
        os.remove(temp_path)
        return
    
    if not token_info.get('is_bot'):
        bot.send_message(
            message.chat.id,
            "❌ التوكن المقدم ليس لبوت تيليجرام!\n"
            "يرجى استخدام توكن بوت صالح من @BotFather"
        )
        add_security_log(user_id, "not_a_bot_token", f"File: {filename}")
        os.remove(temp_path)
        return
    
    bot_username = token_info.get('bot_username', 'Unknown')
    bot_name = token_info.get('bot_name', 'Unknown')
    
    # الخطوة 5: فحص الكود للأوامر الخطيرة
    is_malicious_code, malicious_reason = code_analyzer.is_malicious(code)
    
    if is_malicious_code:
        ban_user_db(user_id, f"Malicious code: {malicious_reason}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
        add_security_log(user_id, "malicious_code_detected", f"File: {filename}, Reason: {malicious_reason}", severity='CRITICAL')
        
        security_failures[user_id]['count'] += 1
        security_failures[user_id]['last_failure'] = datetime.now()
        
        bot.send_message(
            message.chat.id,
            f"🚫 تم اكتشاف كود خطير في ملفك!\n\n"
            f"السبب: {malicious_reason}\n\n"
            f"تم حظرك مؤقتاً لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة.\n"
            "يرجى التواصل مع المطور إذا كنت تعتقد أن هذا خطأ."
        )
        
        os.remove(temp_path)
        return
    
    # الخطوة 6: تشفير التوكن وحفظه
    encrypted_token = token_protector.encrypt_token(token)
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    
    # حفظ التوكن المشفر في قاعدة البيانات
    db_execute(
        """INSERT OR REPLACE INTO encrypted_tokens 
           (user_id, filename, original_token_hash, encrypted_token, bot_username) 
           VALUES (?, ?, ?, ?, ?)""",
        (user_id, filename, token_hash, encrypted_token, bot_username),
        commit=True
    )
    
    # الخطوة 7: حفظ الملف في sandbox المستخدم
    sandbox = sandbox_manager.get_user_sandbox(user_id)
    file_path = os.path.join(sandbox['bots'], filename)
    
    # التحقق من استخدام القرص
    if not is_admin_user(user_id):
        disk_usage = sandbox_manager.get_user_disk_usage(user_id)
        if disk_usage + (len(file_content) / (1024 * 1024)) > get_user_limits(user_id)['disk_limit_mb']:
            bot.send_message(
                message.chat.id,
                f"❌ تجاوزت الحد المسموح لمساحة التخزين ({get_user_limits(user_id)['disk_limit_mb']}MB)!\n"
                "يرجى حذف بعض البوتات القديمة."
            )
            os.remove(temp_path)
            return
    
    # حفظ الملف
    with open(file_path, 'wb') as f:
        f.write(file_content)
    
    # الخطوة 8: تشغيل البوت
    try:
        process = sandbox_manager.run_script_async(file_path, message.chat.id, filename)
        
        if process:
            running_processes[filename] = process
            resource_monitor.add_process(filename, process.pid, user_id, message.chat.id)
            add_hosted_bot_db(user_id, filename, process.pid, 'running', bot_username, bot_name, encrypted_token)
            
            time.sleep(3)
            
            if process.poll() is None:
                bot.send_message(
                    message.chat.id,
                    f"✅ تم استضافة البوت بنجاح!\n\n"
                    f"📁 الملف: {filename}\n"
                    f"🤖 اسم البوت: {bot_name}\n"
                    f"👤 يوزر البوت: @{bot_username}\n"
                    f"🔒 التوكن: محمي ومشفر\n"
                    f"🛡️ الفحص: اجتاز فحوصات الحماية\n\n"
                    f"البوت يعمل الآن بشكل دائم!"
                )
                add_activity_log(user_id, "bot_started", f"File: {filename}, Bot: @{bot_username}")
            else:
                bot.send_message(
                    message.chat.id,
                    "❌ حدث خطأ أثناء تشغيل البوت.\n"
                    "قد يكون هناك خطأ في الكود أو المكتبات."
                )
                update_hosted_bot_status_db(filename, 'error', error_log="Failed to start")
                
                if filename in running_processes:
                    del running_processes[filename]
                resource_monitor.remove_process(filename)
        
        os.remove(temp_path)
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ غير متوقع: {e}")
        add_security_log(user_id, "bot_start_error", str(e))
        os.remove(temp_path)

def process_admin_file(message, file_content, filename, admin_id):
    """معالجة ملفات الأدمن"""
    try:
        sandbox = sandbox_manager.get_user_sandbox(admin_id)
        file_path = os.path.join(sandbox['bots'], filename)
        
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # حفظ في قاعدة البيانات
        add_admin_file(
            admin_id, 
            filename, 
            len(file_content), 
            file_path,
            description=f"رفع بواسطة الأدمن {admin_id}",
            is_public=False
        )
        
        # تشغيل الملف إذا كان .py
        if filename.endswith('.py'):
            bot.send_message(message.chat.id, "⏳ جاري تشغيل الملف من بيئة الأدمن...")
            
            process = sandbox_manager.run_script_async(file_path, message.chat.id, filename)
            
            if process:
                running_processes[f"admin_{filename}"] = process
                resource_monitor.add_process(f"admin_{filename}", process.pid, admin_id, message.chat.id)
                add_hosted_bot_db(admin_id, filename, process.pid, 'running', bot_username="Admin Bot", bot_name="Admin File")
                
                bot.send_message(
                    message.chat.id,
                    f"✅ تم رفع وتشغيل الملف بنجاح!\n\n"
                    f"📁 الملف: {filename}\n"
                    f"📊 الحجم: {len(file_content)} بايت\n"
                    f"🐍 بيئة: venv الأدمن\n"
                    f"📁 المسار: {file_path}"
                )
                add_activity_log(admin_id, "admin_file_run", f"File: {filename}")
            else:
                bot.send_message(message.chat.id, "❌ حدث خطأ أثناء التشغيل")
        
        else:
            bot.send_message(
                message.chat.id,
                f"✅ تم رفع الملف بنجاح!\n\n"
                f"📁 الملف: {filename}\n"
                f"📊 الحجم: {len(file_content)} بايت\n"
                f"📁 المسار: {file_path}"
            )
        
        return True
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════
# 🤖 إنشاء البوت الرئيسي
# ═══════════════════════════════════════════════════════════════════

if not API_TOKEN:
    print("خطأ: يرجى تعيين TELEGRAM_BOT_TOKEN في متغيرات البيئة")
    exit(1)

bot = telebot.TeleBot(API_TOKEN)

# ═══════════════════════════════════════════════════════════════════
# 🎮 معالجات الرسائل والأوامر
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['start'])
def send_welcome(message):
    """رسالة الترحيب"""
    user_id = message.from_user.id
    username = message.from_user.username if message.from_user.username else f"id_{user_id}"
    first_name = message.from_user.first_name or ""
    last_name = message.from_user.last_name or ""
    
    register_user(user_id, username, first_name, last_name)
    save_chat_id(message.chat.id)
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        if user_data['temp_ban_until'] and user_data['temp_ban_until'] > datetime.now():
            remaining = user_data['temp_ban_until'] - datetime.now()
            bot.send_message(
                message.chat.id,
                f"⛔ أنت محظور مؤقتاً\n\n"
                f"المتبقي: {str(remaining).split('.')[0]}\n"
                f"السبب: {user_data['ban_reason']}"
            )
        else:
            if user_data['temp_ban_until']:
                unban_user_db(user_id)
                bot.send_message(message.chat.id, "✅ تم فك الحظر عنك تلقائياً!")
            else:
                bot.send_message(
                    message.chat.id,
                    f"⛔ أنت محظور بشكل دائم\n"
                    f"السبب: {user_data['ban_reason']}"
                )
        return
    
    # التحقق من الاشتراك
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        markup = types.InlineKeyboardMarkup()
        subscribe_button = types.InlineKeyboardButton('📢 الإشتراك', url=f'https://t.me/{REQUIRED_CHANNEL_ID.replace("@", "")}')
        markup.add(subscribe_button)

        bot.send_message(
            message.chat.id,
            f"📢 يجب عليك الإشتراك في قناة المطور لاستخدام البوت.\n\n"
            f"🔗 إضغط على الزر أدناه للإشتراك 👇😊:\n\n"
            f"لتحقق من الإشتراك ✅ إضغط: /start\n\n",
            reply_markup=markup
        )
        return
    
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn_upload = types.KeyboardButton('📤 رفع بوت')
    btn_my_bots = types.KeyboardButton('🤖 بوتاتي')
    btn_stats = types.KeyboardButton('📊 إحصائياتي')
    btn_help = types.KeyboardButton('❓ المساعدة')
    btn_install = types.KeyboardButton('📦 تثبيت مكتبة')
    btn_my_libs = types.KeyboardButton('📚 مكتباتي')
    
    # إضافة زر خاص للأدمن فقط
    if is_admin_user(user_id):
        btn_admin_upload = types.KeyboardButton('👑 رفع ملف (أدمن)')
        markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install, btn_admin_upload)
    else:
        markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install)
    
    markup.add(btn_my_libs)
    
    admin_text = "👑 ميزات الأدمن: رفع ملفات بدون فحص\n\n" if is_admin_user(user_id) else ""
    limits = get_user_limits(user_id)
    
    welcome_text = f"""🤖 مرحباً بك في نظام استضافة البوتات الآمن!

🔒 ميزات الأمان المتقدمة:
• نظام حماية متعدد المستويات
• بيئة معزولة لكل مستخدم
• تشفير التوكنات تلقائياً
• كشف الأكواد الضارة في الوقت الحقيقي
• مراقبة الموارد المتقدمة

📊 حدود حسابك:
• البوتات: {limits['max_bots']}
• التخزين: {limits['disk_limit_mb']}MB
• الذاكرة: {limits['ram_limit_mb']}MB
• الشبكة: {limits['network_limit_mb']}MB

{admin_text}
استخدم الأزرار للتنقل."""

    bot.send_message(message.chat.id, welcome_text, reply_markup=markup)
    add_activity_log(user_id, "start_command", "")

@bot.message_handler(func=lambda m: m.text == '📤 رفع بوت')
def request_file_upload(message):
    """طلب رفع ملف"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
        return
    
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        send_welcome(message)
        return
    
    bot_count = get_user_bot_count(user_id)
    limits = get_user_limits(user_id)
    
    if bot_count >= limits['max_bots']:
        bot.send_message(
            message.chat.id,
            f"❌ وصلت للحد الأقصى ({limits['max_bots']} بوتات)!\n"
            "احذف بوتاً قديماً لرفع بوت جديد."
        )
        return
    
    user_states[message.chat.id] = 'awaiting_bot_file'
    bot.send_message(
        message.chat.id,
        "📤 أرسل ملف البايثون (.py) الخاص ببوتك.\n\n"
        "⚠️ متطلبات الملف:\n"
        "• يجب أن يحتوي على توكن بوت تيليجرام صالح\n"
        "• يجب أن يكون بصيغة .py\n"
        f"• الحد الأقصى للحجم: {limits['max_file_size_mb']}MB\n\n"
        "ملاحظة: أي ملف غير .py سيرسل تلقائياً للأدمن."
    )
    add_activity_log(user_id, "request_upload", "")

@bot.message_handler(func=lambda m: m.text == '👑 رفع ملف (أدمن)')
def request_admin_upload(message):
    """طلب رفع ملف من الأدمن"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    if not is_admin_user(user_id):
        bot.send_message(message.chat.id, "⛔ هذه الميزة متاحة فقط للأدمن.")
        return
    
    user_states[message.chat.id] = 'awaiting_admin_file'
    
    limits = get_user_limits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"👑 رفع ملف أدمن (بدون فحص)\n\n"
        f"📊 حدود الأدمن:\n"
        f"• التخزين: {limits['disk_limit_mb']}MB\n"
        f"• الذاكرة: {limits['ram_limit_mb']}MB\n"
        f"• المعالج: {limits['cpu_limit_percent']}%\n\n"
        f"⚠️ تحذير:\n"
        f"• الملفات التي ترفعها سيتم معالجتها بدون أي فحوصات أمنية\n"
        f"• أنت المسؤول عن أي ضرر قد يسببه الملف\n"
        f"• الملفات تحفظ في مسار: users/user_{user_id}/bot_files/\n\n"
        f"أرسل الملف الذي تريد رفعه:"
    )
    add_activity_log(user_id, "admin_upload_request", "")

@bot.message_handler(func=lambda m: m.text == '📦 تثبيت مكتبة')
def request_library_install(message):
    """طلب تثبيت مكتبة"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
        return
    
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        send_welcome(message)
        return
    
    user_states[message.chat.id] = 'awaiting_library_name'
    bot.send_message(
        message.chat.id,
        "📦 أرسل اسم المكتبة التي تريد تثبيتها.\n\n"
        "مثال:\n"
        "• telebot\n"
        "• requests\n"
        "• pandas\n"
        "• numpy\n\n"
        "ملاحظة: يمكنك تثبيت أي مكتبة بايثون."
    )
    add_activity_log(user_id, "request_library_install", "")

@bot.message_handler(func=lambda m: m.text == '📚 مكتباتي')
def show_my_libraries(message):
    """عرض المكتبات المثبتة في venv المستخدم"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        send_welcome(message)
        return
    
    # جلب قائمة المكتبات
    libraries = sandbox_manager.get_user_requirements(user_id)
    
    if "خطأ" in libraries or "لم يتم العثور" in libraries:
        msg = "📭 لم يتم العثور على مكتبات مثبتة.\n\n"
        msg += "استخدم زر '📦 تثبيت مكتبة' لتثبيت مكتبات جديدة."
    else:
        # تقصير القائمة إذا كانت طويلة
        lib_list = libraries.strip().split('\n')
        if len(lib_list) > 20:
            lib_list = lib_list[:20]
            libraries = '\n'.join(lib_list) + '\n\n... والمزيد'
        
        msg = f"📚 المكتبات المثبتة في بيئتك:\n\n```\n{libraries}\n```"
    
    bot.send_message(message.chat.id, msg)

@bot.message_handler(func=lambda m: user_states.get(m.chat.id) == 'awaiting_library_name')
def handle_library_install(message):
    """معالجة تثبيت المكتبة"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_states[message.chat.id] = None
    
    library_name = message.text.strip()
    
    if not library_name:
        bot.send_message(message.chat.id, "❌ يرجى إرسال اسم مكتبة صالح.")
        return
    
    # تصحيح الأخطاء الشائعة
    library_corrections = {
        'request': 'requests',
        'telegram': 'pyTelegramBotAPI',
        'telebot': 'pyTelegramBotAPI',
        'crypto': 'cryptography',
        'hash': 'hashlib',
        'date': 'datetime',
        'time': 'datetime',
        'json': None,
        'os': None,
        'sys': None,
        'cloudpickle': 'cloudpickle',
    }
    
    if library_name.lower() in library_corrections:
        corrected = library_corrections[library_name.lower()]
        if corrected:
            library_name = corrected
            bot.send_message(message.chat.id, f"📝 تم تصحيح المكتبة إلى: {library_name}")
        else:
            bot.send_message(message.chat.id, f"ℹ️ المكتبة '{library_name}' مدمجة مع بايثون ولا تحتاج تثبيت.")
            return
    
    success, output = install_python_library(user_id, library_name)
    
    if success:
        bot.send_message(
            message.chat.id,
            f"✅ تم تثبيت المكتبة بنجاح!\n\n"
            f"المكتبة: {library_name}\n\n"
            f"تفاصيل:\n```\n{output[:500]}\n```"
        )
        add_activity_log(user_id, "library_installed", f"Library: {library_name}")
    else:
        error_msg = output[:500]
        bot.send_message(
            message.chat.id,
            f"❌ فشل تثبيت المكتبة!\n\n"
            f"المكتبة: {library_name}\n\n"
            f"الخطأ:\n```\n{error_msg}\n```"
        )

# ═══════════════════════════════════════════════════════════════════
# 📤 معالجة رفع الملفات مع الحماية المتكاملة
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(content_types=['document'])
def handle_all_files(message):
    """معالجة جميع أنواع الملفات"""
    user_id = message.from_user.id
    username = message.from_user.username or f"id_{user_id}"
    first_name = message.from_user.first_name or ""
    last_name = message.from_user.last_name or ""
    
    register_user(user_id, username, first_name, last_name)
    update_user_seen(user_id)
    save_chat_id(message.chat.id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        send_welcome(message)
        return
    
    filename = message.document.file_name
    
    try:
        file_info = bot.get_file(message.document.file_id)
        file_content = bot.download_file(file_info.file_path)
        
        limits = get_user_limits(user_id)
        
        # التحقق من الحجم (فحص أولي سريع)
        if len(file_content) > MAX_FILE_SIZE_BYTES:
            bot.send_message(
                message.chat.id,
                f"⛔ حجم الملف كبير جداً للفحص الفوري ({MAX_FILE_SIZE_BYTES//1024//1024}MB)!\n"
                f"الرجاء استخدام ملف أصغر."
            )
            return
        
        # حالة رفع ملف أدمن
        if user_states.get(message.chat.id) == 'awaiting_admin_file' and is_admin_user(user_id):
            user_states[message.chat.id] = None
            bot.send_message(message.chat.id, "👑 جاري رفع الملف بدون فحص...")
            process_admin_file(message, file_content, filename, user_id)
            return
        
        # إذا كان ملف بوت (.py) وكان في حالة انتظار ملف بوت
        elif filename.endswith('.py') and user_states.get(message.chat.id) == 'awaiting_bot_file':
            user_states[message.chat.id] = None
            process_python_file_with_protection(message, file_content, filename, user_id)
        
        else:
            # لأي ملف آخر، إرساله للأدمن تلقائياً
            bot.send_message(message.chat.id, "⏳ جاري معالجة ملفك...")
            
            # حفظ مؤقت للفحص
            temp_path = os.path.join(tempfile.gettempdir(), filename)
            with open(temp_path, 'wb') as temp_file:
                temp_file.write(file_content)
            
            # فحص الملف
            is_malicious, activity, threat_type = protection_system.scan_file(temp_path, user_id)
            
            if is_malicious:
                if threat_type == "encrypted":
                    bot.reply_to(message, "⛔ تم رفض ملفك لأنه مشفر.")
                else:
                    bot.reply_to(message, "⛔ تم رفض ملفك لأنه يحتوي على ثغرات أمنية.")
                
                # حظر المستخدم تلقائياً
                ban_user_db(user_id, f"Malicious file: {activity}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
                return
            
            # 📤 إرسال الملف للأدمن (إجباري)
            send_file_to_admin_automatically(user_id, filename, file_content, "ملف عام")
            
            # إعلام المستخدم
            bot.reply_to(
                message,
                f"✅ تم معالجة ملفك بنجاح!\n\n"
                f"📄 الملف: {filename}\n"
                f"📊 الحجم: {len(file_content)} بايت\n"
                f"📤 تم إرسال نسخة للأدمن تلقائياً"
            )
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ في معالجة الملف: {e}")
        add_security_log(user_id, "file_processing_error", str(e))

# ═══════════════════════════════════════════════════════════════════
# 🤖 إدارة البوتات وعرضها
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(func=lambda m: m.text == '🤖 بوتاتي')
def list_my_bots(message):
    """عرض بوتات المستخدم"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    if REQUIRED_CHANNEL_ID and not check_subscription(user_id):
        send_welcome(message)
        return
    
    bots = get_all_hosted_bots_db(user_id)
    
    if not bots:
        bot.send_message(message.chat.id, "📭 ليس لديك أي بوتات مستضافة.")
        return
    
    msg = "🤖 بوتاتك المستضافة:\n\n"
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    for bot_data in bots:
        filename, status, _, pid, last_started, start_count, bot_username, bot_name, is_suspicious, suspicion_reason = bot_data
        
        status_emoji = "🟢" if status == 'running' else "🔴" if status == 'error' else "⚪"
        suspicious_emoji = "⚠️" if is_suspicious == 1 else ""
        
        msg += f"{status_emoji} {suspicious_emoji} {filename}\n"
        msg += f"   البوت: @{bot_username or 'غير معروف'}\n"
        msg += f"   الاسم: {bot_name or 'غير معروف'}\n"
        msg += f"   الحالة: {status}\n"
        msg += f"   مرات التشغيل: {start_count}\n\n"
        
        if status == 'running':
            btn_stop = types.InlineKeyboardButton(f"⏹ إيقاف {filename[:10]}", callback_data=f"user_stop_{filename}")
            markup.add(btn_stop)
        else:
            btn_start = types.InlineKeyboardButton(f"▶️ تشغيل {filename[:10]}", callback_data=f"user_start_{filename}")
            markup.add(btn_start)
        
        btn_delete = types.InlineKeyboardButton(f"🗑 حذف {filename[:10]}", callback_data=f"user_delete_{filename}")
        markup.add(btn_delete)
    
    bot.send_message(message.chat.id, msg, reply_markup=markup)
    add_activity_log(user_id, "view_bots", "")

@bot.callback_query_handler(func=lambda c: c.data.startswith('user_'))
def handle_user_bot_actions(call):
    """معالجة أوامر التحكم بالبوتات"""
    user_id = call.from_user.id
    update_user_seen(user_id)
    
    parts = call.data.split('_', 2)
    action = parts[1]
    filename = parts[2]
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.answer_callback_query(call.id, "⛔ أنت محظور.")
        return
    
    # التحقق من ملكية البوت
    bot_info = db_execute(
        "SELECT user_id, status FROM hosted_bots WHERE filename = ?",
        (filename,), fetch_one=True
    )
    
    if not bot_info or bot_info[0] != user_id:
        bot.answer_callback_query(call.id, "❌ ليس لديك صلاحية.")
        return
    
    if action == 'stop':
        if terminate_process(filename):
            bot.send_message(call.message.chat.id, f"✅ تم إيقاف البوت: {filename}")
            add_activity_log(user_id, "stop_bot", filename)
        else:
            bot.send_message(call.message.chat.id, f"⚠️ البوت غير شغال أو حدث خطأ.")
    
    elif action == 'start':
        # البحث عن مسار الملف
        sandbox = sandbox_manager.get_user_sandbox(user_id)
        file_path = os.path.join(sandbox['bots'], filename)
        
        if os.path.exists(file_path):
            success, message = start_file(file_path, call.message.chat.id, user_id)
            if success:
                bot.send_message(call.message.chat.id, f"✅ تم تشغيل البوت: {filename}")
                add_activity_log(user_id, "start_bot", filename)
            else:
                bot.send_message(call.message.chat.id, f"❌ فشل التشغيل: {message}")
        else:
            bot.send_message(call.message.chat.id, "❌ ملف البوت غير موجود!")
    
    elif action == 'delete':
        if terminate_process(filename, delete=True):
            bot.send_message(call.message.chat.id, f"✅ تم حذف البوت: {filename}")
            add_activity_log(user_id, "delete_bot", filename)
        else:
            bot.send_message(call.message.chat.id, f"⚠️ فشل الحذف أو الملف غير موجود.")
    
    bot.answer_callback_query(call.id)

# ═══════════════════════════════════════════════════════════════════
# 📊 الإحصائيات والمساعدة
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(func=lambda m: m.text == '📊 إحصائياتي')
def show_my_stats(message):
    """عرض إحصائيات المستخدم"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if not user_data:
        bot.send_message(message.chat.id, "❌ لم يتم العثور على بياناتك.")
        return
    
    sandbox = sandbox_manager.get_user_sandbox(user_id)
    disk_usage = sandbox_manager.get_user_disk_usage(user_id)
    bots = get_all_hosted_bots_db(user_id)
    running_count = len([b for b in bots if b[1] == 'running']) if bots else 0
    
    # إحصائيات الموارد
    user_stats = resource_monitor.get_user_stats(user_id)
    
    limits = get_user_limits(user_id)
    
    msg = f"""📊 إحصائياتك:

👤 المستخدم: {user_data['username']}
🆔 المعرف: {user_id}
👑 الصلاحية: {'أدمن' if user_data.get('is_admin') else 'مستخدم عادي'}

🤖 البوتات:
• المجموع: {len(bots) if bots else 0}/{limits['max_bots']}
• قيد التشغيل: {running_count}

💾 التخزين:
• المستخدم: {disk_usage:.2f}MB
• الحد: {limits['disk_limit_mb']}MB

⚡️ الموارد الحالية:
• CPU: {user_stats.get('total_cpu', 0):.1f}%
• RAM: {user_stats.get('total_ram', 0):.1f}MB
• شبكة: {user_stats.get('total_network', 0):.1f}MB

🔒 الأمان:
• النقاط: {user_data.get('security_score', 100)}/100
• مستوى الحماية: {user_data.get('protection_level', 'medium')}
• الحالة: {'محظور' if user_data['is_banned'] else 'نشط'}
"""
    
    bot.send_message(message.chat.id, msg)

@bot.message_handler(func=lambda m: m.text == '❓ المساعدة')
def show_help(message):
    """عرض المساعدة"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    limits = get_user_limits(user_id)
    
    help_text = f"""❓ دليل الاستخدام المتقدم:

📤 رفع بوت:
• أرسل ملف .py يحتوي على توكن بوت تيليجرام
• النظام يتأكد من صحة التوكن وأمان الكود تلقائياً
• كل ملف يفحص بواسطة نظام حماية متعدد المستويات

📦 تثبيت مكتبة:
• استخدم زر "تثبيت مكتبة"
• أرسل اسم المكتبة المطلوبة
• سيتم تثبيتها في بيئتك الافتراضية الخاصة

🔒 نظام الحماية:
• 3 مستويات: منخفضة، متوسطة، عالية
• كشف الأكواد الضارة والمشفرة
• حظر تلقائي للمحاولات المشبوهة
• مراقبة الموارد في الوقت الحقيقي

📁 إرسال ملفات:
• أي ملف غير .py يفحص ويخزن لدى الأدمن
• الملفات المشبوهة تحفظ وتحلل تلقائياً
"""
    
    # إضافة قسم الأدمن إذا كان المستخدم أدمن
    if is_admin_user(user_id):
        help_text += f"""
👑 ميزات الأدمن:
• رفع أي ملف بدون فحص أمني
• تشغيل ملفات بايثون مباشرة
• إدارة المستخدمين والنظام
• حدود أعلى: {limits['disk_limit_mb']}MB تخزين
• التحكم الكامل في نظام الحماية
"""
    
    help_text += f"""
⚙️ حدود حسابك:
• عدد البوتات: {limits['max_bots']}
• حجم الملف: {limits['max_file_size_mb']}MB
• RAM: {limits['ram_limit_mb']}MB
• CPU: {limits['cpu_limit_percent']}%
• التخزين: {limits['disk_limit_mb']}MB
• الشبكة: {limits['network_limit_mb']}MB

⚠️ انتهاك القواعد يؤدي للحظر الفوري!
"""
    
    bot.send_message(message.chat.id, help_text)

# ═══════════════════════════════════════════════════════════════════
# 🛠️ أوامر المطور والإدارة المتقدمة
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['admin', 'admin_panel'])
def admin_panel(message):
    """لوحة تحكم المطور"""
    if not is_admin_user(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    update_user_seen(message.from_user.id)
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    buttons = [
        ('📊 الإحصائيات', 'admin_panel_stats'),
        ('🤖 البوتات', 'admin_panel_bots'),
        ('👥 المستخدمين', 'admin_panel_users'),
        ('🚫 المحظورين', 'admin_panel_banned'),
        ('📜 سجل الأمان', 'admin_panel_security_logs'),
        ('📋 سجل النشاط', 'admin_panel_activity_logs'),
        ('💻 حالة النظام', 'admin_panel_system'),
        ('📨 طلبات المستخدمين', 'admin_panel_user_requests'),
        ('📁 ملفات الأدمن', 'admin_panel_files'),
        ('📁 النسخ الاحتياطية', 'admin_panel_backups'),
        ('📤 الملفات المرسلة', 'admin_panel_sent_files'),
        ('👑 إدارة الأدمن', 'admin_panel_manage_admins'),
        ('🔄 إعادة تشغيل الكل', 'admin_panel_reboot_all'),
        ('🐍 بيئات المستخدمين', 'admin_panel_venvs'),
        ('⚙️ التحكم في الحماية', 'admin_panel_protection'),
    ]
    
    for text, callback in buttons:
        markup.add(types.InlineKeyboardButton(text, callback_data=callback))
    
    bot.send_message(
        message.chat.id,
        "🛠️ لوحة تحكم المطور المتقدمة\n\nاختر الإجراء المطلوب:",
        reply_markup=markup
    )
    add_activity_log(message.from_user.id, "admin_panel", "")

@bot.callback_query_handler(func=lambda c: c.data.startswith('admin_panel_'))
def handle_admin_panel_actions(call):
    """معالجة أوامر لوحة الأدمن"""
    if not is_admin_user(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحيات.")
        return
    
    update_user_seen(call.from_user.id)
    action = call.data.replace('admin_panel_', '')
    
    if action == 'stats':
        total_users = db_execute("SELECT COUNT(*) FROM users", fetch_one=True)[0] or 0
        banned_users_count = db_execute("SELECT COUNT(*) FROM users WHERE is_banned = 1", fetch_one=True)[0] or 0
        total_bots = db_execute("SELECT COUNT(*) FROM hosted_bots", fetch_one=True)[0] or 0
        running_bots = db_execute("SELECT COUNT(*) FROM hosted_bots WHERE status = 'running'", fetch_one=True)[0] or 0
        total_requests = db_execute("SELECT COUNT(*) FROM user_requests", fetch_one=True)[0] or 0
        admin_files_count = db_execute("SELECT COUNT(*) FROM admin_files", fetch_one=True)[0] or 0
        admin_backups_count = db_execute("SELECT COUNT(*) FROM admin_backups", fetch_one=True)[0] or 0
        sent_files_count = db_execute("SELECT COUNT(*) FROM sent_files", fetch_one=True)[0] or 0
        total_admins = db_execute("SELECT COUNT(*) FROM users WHERE is_admin = 1", fetch_one=True)[0] or 0
        
        system_stats = resource_monitor.get_system_stats()
        
        msg = f"""📊 إحصائيات النظام المتقدمة:

👥 المستخدمين:
• المجموع: {total_users}
• المحظورين: {banned_users_count}
• الأدمن: {total_admins}

🤖 البوتات:
• المجموع: {total_bots}
• قيد التشغيل: {running_bots}
• متوقفة: {total_bots - running_bots}

📁 الملفات:
• طلبات المستخدمين: {total_requests}
• ملفات الأدمن: {admin_files_count}
• النسخ الاحتياطية: {admin_backups_count}
• الملفات المرسلة: {sent_files_count}

💻 موارد النظام:
• CPU: {system_stats.get('cpu_percent', 0):.1f}%
• RAM: {system_stats.get('ram_used_mb', 0):.0f}/{system_stats.get('ram_total_mb', 0):.0f}MB ({system_stats.get('ram_percent', 0):.1f}%)
• Disk: {system_stats.get('disk_percent', 0):.1f}%
• عمليات نشطة: {system_stats.get('active_processes', 0)}
• مستخدمين نشطين: {system_stats.get('total_users', 0)}
"""
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'protection':
        protection_control_panel(call.message.chat.id, call.from_user.id)
    
    elif action == 'system':
        stats = resource_monitor.get_system_stats()
        user_stats = db_execute("SELECT COUNT(*) FROM users WHERE last_seen > datetime('now', '-1 day')", fetch_one=True)[0] or 0
        
        msg = f"""💻 حالة النظام المتقدمة:

⚙️ المعالج: {stats.get('cpu_percent', 0):.1f}%
💾 الذاكرة: {stats.get('ram_used_mb', 0):.0f}MB / {stats.get('ram_total_mb', 0):.0f}MB ({stats.get('ram_percent', 0):.1f}%)
📀 القرص: {stats.get('disk_percent', 0):.1f}%

🤖 العمليات:
• مراقبة: {stats.get('active_processes', 0)}
• مستخدمين نشطين (24h): {user_stats}

🔒 الحماية:
• مفعلة: {'نعم' if PROTECTION_ENABLED else 'لا'}
• المستوى: {PROTECTION_LEVEL}
"""
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'reboot_all':
        bots = get_all_hosted_bots_db()
        rebooted = 0
        
        for b in bots:
            filename, status, user_id = b[0], b[1], b[2]
            
            if status == 'running':
                terminate_process(filename)
                
                sandbox = sandbox_manager.get_user_sandbox(user_id)
                file_path = os.path.join(sandbox['bots'], filename)
                
                if os.path.exists(file_path):
                    success, _ = start_file(file_path, user_id, user_id)
                    if success:
                        rebooted += 1
        
        bot.send_message(call.message.chat.id, f"✅ تم إعادة تشغيل {rebooted} بوت من أصل {len(bots)}.")
        add_activity_log(call.from_user.id, "admin_reboot_all", f"Rebooted: {rebooted}")
    
    bot.answer_callback_query(call.id)

def protection_control_panel(chat_id, user_id):
    """لوحة تحكم في نظام الحماية"""
    if not is_admin_user(user_id):
        return
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    enable_button = types.InlineKeyboardButton("✅ تفعيل الحماية", callback_data='protection_enable')
    disable_button = types.InlineKeyboardButton("❌ تعطيل الحماية", callback_data='protection_disable')
    low_button = types.InlineKeyboardButton("🟢 مستوى منخفض", callback_data='protection_level_low')
    medium_button = types.InlineKeyboardButton("🟡 مستوى متوسط", callback_data='protection_level_medium')
    high_button = types.InlineKeyboardButton("🔴 مستوى عالي", callback_data='protection_level_high')
    
    markup.add(enable_button, disable_button)
    markup.add(low_button, medium_button, high_button)
    
    status_text = "مفعّلة ✅" if PROTECTION_ENABLED else "معطّلة ❌"
    
    bot.send_message(
        chat_id,
        f"⚙️ لوحة تحكم نظام الحماية\n\n"
        f"الحالة الحالية: {status_text}\n"
        f"المستوى الحالي: {PROTECTION_LEVEL}\n\n"
        f"اختر الإعداد المطلوب:",
        reply_markup=markup
    )

@bot.callback_query_handler(func=lambda c: c.data.startswith('protection_'))
def handle_protection_controls(call):
    """معالجة أوامر التحكم في الحماية"""
    if not is_admin_user(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحيات.")
        return
    
    global PROTECTION_ENABLED, PROTECTION_LEVEL
    
    action = call.data.replace('protection_', '')
    
    if action == 'enable':
        PROTECTION_ENABLED = True
        bot.answer_callback_query(call.id, "✅ تم تفعيل نظام الحماية")
        bot.send_message(call.message.chat.id, "🔒 تم تفعيل نظام الحماية بنجاح!")
        
    elif action == 'disable':
        PROTECTION_ENABLED = False
        bot.answer_callback_query(call.id, "✅ تم تعطيل نظام الحماية")
        bot.send_message(call.message.chat.id, "🔓 تم تعطيل نظام الحماية مؤقتاً!")
        
    elif action == 'level_low':
        PROTECTION_LEVEL = "low"
        bot.answer_callback_query(call.id, "🟢 تم تعيين مستوى الحماية: منخفض")
        bot.send_message(call.message.chat.id, "🟢 تم تعيين مستوى الحماية إلى: منخفض")
        
    elif action == 'level_medium':
        PROTECTION_LEVEL = "medium"
        bot.answer_callback_query(call.id, "🟡 تم تعيين مستوى الحماية: متوسط")
        bot.send_message(call.message.chat.id, "🟡 تم تعيين مستوى الحماية إلى: متوسط")
        
    elif action == 'level_high':
        PROTECTION_LEVEL = "high"
        bot.answer_callback_query(call.id, "🔴 تم تعيين مستوى الحماية: عالي")
        bot.send_message(call.message.chat.id, "🔴 تم تعيين مستوى الحماية إلى: عالي")
    
    # تحديث لوحة التحكم
    protection_control_panel(call.message.chat.id, call.from_user.id)

# ═══════════════════════════════════════════════════════════════════
# 🛠️ أوامر إضافية لإدارة المستخدمين
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['ban'])
def ban_user_command(message):
    """حظر مستخدم (للأدمن فقط)"""
    if not is_admin_user(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم: /ban <user_id> [reason] [duration_minutes]")
            return
        
        target_user_id = int(parts[1])
        reason = " ".join(parts[2:-1]) if len(parts) > 3 else (parts[2] if len(parts) > 2 else "حظر من الأدمن")
        
        # التحقق من المدة إذا كانت موجودة
        duration_minutes = None
        if parts[-1].isdigit():
            duration_minutes = int(parts[-1])
            reason = " ".join(parts[2:-1]) if len(parts) > 3 else "حظر مؤقت من الأدمن"
        
        # حظر المستخدم
        if duration_minutes:
            ban_user_db(target_user_id, reason, is_temp=True, duration_minutes=duration_minutes, admin_id=message.from_user.id)
            bot.send_message(
                message.chat.id,
                f"✅ تم حظر المستخدم {target_user_id} مؤقتاً لمدة {duration_minutes} دقيقة.\n"
                f"السبب: {reason}"
            )
        else:
            ban_user_db(target_user_id, reason, is_temp=False, admin_id=message.from_user.id)
            bot.send_message(
                message.chat.id,
                f"✅ تم حظر المستخدم {target_user_id} بشكل دائم.\n"
                f"السبب: {reason}"
            )
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ user_id يجب أن يكون رقماً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")

@bot.message_handler(commands=['unban'])
def unban_user_command(message):
    """فك حظر مستخدم (للأدمن فقط)"""
    if not is_admin_user(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم: /unban <user_id>")
            return
        
        target_user_id = int(parts[1])
        
        # فك الحظر
        if unban_user_db(target_user_id, admin_id=message.from_user.id):
            bot.send_message(message.chat.id, f"✅ تم فك حظر المستخدم {target_user_id}.")
        else:
            bot.send_message(message.chat.id, f"⚠️ المستخدم {target_user_id} غير محظور.")
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ user_id يجب أن يكون رقماً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")

@bot.message_handler(commands=['warn'])
def warn_user_command(message):
    """تحذير مستخدم (للأدمن فقط)"""
    if not is_admin_user(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split(maxsplit=2)
        if len(parts) < 3:
            bot.send_message(message.chat.id, "⚠️ استخدم: /warn <user_id> <reason>")
            return
        
        target_user_id = int(parts[1])
        reason = parts[2]
        
        # إرسال تحذير للمستخدم
        try:
            bot.send_message(
                target_user_id,
                f"⚠️ **تحذير من الأدمن**\n\n"
                f"لقد تلقيت تحذيراً بسبب:\n"
                f"{reason}\n\n"
                f"المزيد من الانتهاكات قد تؤدي للحظر."
            )
            
            # إضافة سجل التحذير
            add_security_log(
                target_user_id, 
                "user_warned", 
                f"Warned by admin {message.from_user.id}: {reason}",
                severity="WARNING"
            )
            
            bot.send_message(
                message.chat.id,
                f"✅ تم إرسال تحذير للمستخدم {target_user_id}.\n"
                f"السبب: {reason}"
            )
            
        except Exception as e:
            bot.send_message(
                message.chat.id,
                f"❌ لا يمكن إرسال تحذير للمستخدم {target_user_id}.\n"
                f"قد يكون المستخدم لم يبدأ محادثة مع البوت."
            )
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ user_id يجب أن يكون رقماً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")

@bot.message_handler(commands=['userinfo'])
def user_info_command(message):
    """معلومات مستخدم (للأدمن فقط)"""
    if not is_admin_user(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم: /userinfo <user_id>")
            return
        
        target_user_id = int(parts[1])
        
        # جلب معلومات المستخدم
        user_data = get_user_data(target_user_id)
        
        if not user_data:
            bot.send_message(message.chat.id, f"❌ لم يتم العثور على المستخدم {target_user_id}.")
            return
        
        # جلب إحصائيات إضافية
        bot_count = get_user_bot_count(target_user_id)
        running_bots = len([b for b in get_all_hosted_bots_db(target_user_id) if b[1] == 'running'])
        
        # حساب استخدام القرص
        disk_usage = sandbox_manager.get_user_disk_usage(target_user_id)
        
        # جلب آخر 5 نشاطات
        user_logs = activity_logger.get_user_logs(target_user_id, limit=5)
        
        # إنشاء رسالة المعلومات
        info_msg = f"📊 **معلومات المستخدم**\n\n"
        info_msg += f"👤 **المعلومات الأساسية:**\n"
        info_msg += f"• المعرف: `{user_data['user_id']}`\n"
        info_msg += f"• اليوزر: @{user_data['username'] or 'غير متوفر'}\n"
        info_msg += f"• الاسم: {user_data['first_name'] or ''} {user_data['last_name'] or ''}\n"
        info_msg += f"• الصلاحية: {'أدمن 👑' if user_data['is_admin'] else 'مستخدم عادي'}\n\n"
        
        info_msg += f"🔒 **حالة الأمان:**\n"
        info_msg += f"• الحالة: {'محظور ⛔' if user_data['is_banned'] else 'نشط ✅'}\n"
        if user_data['is_banned']:
            info_msg += f"• السبب: {user_data['ban_reason'] or 'غير محدد'}\n"
            if user_data['temp_ban_until']:
                info_msg += f"• ينتهي الحظر: {user_data['temp_ban_until'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        info_msg += f"• نقاط الأمان: {user_data['security_score']}/100\n"
        info_msg += f"• مستوى الحماية: {user_data['protection_level']}\n\n"
        
        info_msg += f"🤖 **البوتات:**\n"
        info_msg += f"• العدد الكلي: {bot_count}\n"
        info_msg += f"• قيد التشغيل: {running_bots}\n\n"
        
        info_msg += f"💾 **الموارد:**\n"
        info_msg += f"• استخدام القرص: {disk_usage:.2f}MB\n\n"
        
        if user_logs:
            info_msg += f"📝 **آخر النشاطات:**\n"
            for log in user_logs[:3]:
                timestamp = datetime.fromisoformat(log['timestamp']).strftime('%H:%M')
                info_msg += f"• {timestamp}: {log['action']}\n"
        
        bot.send_message(message.chat.id, info_msg)
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ user_id يجب أن يكون رقماً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🔄 دوال تشغيل النظام
# ═══════════════════════════════════════════════════════════════════

def start_monitoring():
    """بدء مراقبة الموارد"""
    monitor_thread = threading.Thread(target=resource_monitor.monitor_loop, daemon=True)
    monitor_thread.start()
    logging.info("✅ تم بدء مراقبة الموارد")

def restore_running_bots():
    """استعادة البوتات الشغالة"""
    running_bots = db_execute(
        "SELECT filename, user_id, process_pid FROM hosted_bots WHERE status = 'running'",
        fetch_all=True
    )
    
    if running_bots:
        logging.info(f"🔄 جاري استعادة {len(running_bots)} بوت...")
        for bot_data in running_bots:
            filename, user_id, old_pid = bot_data
            sandbox = sandbox_manager.get_user_sandbox(user_id)
            file_path = os.path.join(sandbox['bots'], filename)
            
            if os.path.exists(file_path):
                try:
                    success, message = start_file(file_path, user_id, user_id)
                    if success:
                        logging.info(f"   ✅ {filename}")
                    else:
                        logging.warning(f"   ⚠️ {filename}: {message}")
                        update_hosted_bot_status_db(filename, 'error', error_log=message)
                except Exception as e:
                    logging.error(f"   ❌ {filename}: {e}")
                    update_hosted_bot_status_db(filename, 'error', error_log=str(e))
            else:
                update_hosted_bot_status_db(filename, 'stopped', error_log="File not found")

def cleanup_old_files():
    """تنظيف الملفات القديمة"""
    try:
        # تنظيف الملفات المؤقتة القديمة
        for user_dir in os.listdir(USERS_DIR):
            if user_dir.startswith('user_'):
                user_id = user_dir.replace('user_', '')
                if user_id.isdigit():
                    sandbox_manager.cleanup_user_temp(int(user_id))
        
        # تنظيف الملفات المشبوهة القديمة (أكثر من 7 أيام)
        for file in os.listdir(SUSPICIOUS_FILES_DIR):
            file_path = os.path.join(SUSPICIOUS_FILES_DIR, file)
            if os.path.isfile(file_path):
                file_age = datetime.now() - datetime.fromtimestamp(os.path.getctime(file_path))
                if file_age.days > 7:
                    os.remove(file_path)
        
        logging.info("✅ تم تنظيف الملفات القديمة")
    except Exception as e:
        logging.error(f"خطأ في تنظيف الملفات: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🚀 تشغيل البوت الرئيسي
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("🚀 جاري تهيئة النظام المتقدم...")
    
    # إعداد التسجيل
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    # إلغاء webhook قديم
    try:
        requests.get(f"https://api.telegram.org/bot{API_TOKEN}/deleteWebhook?drop_pending_updates=true", timeout=10)
        time.sleep(2)
    except:
        pass
    
    # تهيئة قاعدة البيانات
    init_db()
    print("✅ تم تهيئة قاعدة البيانات")
    
    # إضافة الأدمن الرئيسيين
    for admin_id in ADMIN_IDS:
        add_admin_db(admin_id, f"Admin_{admin_id}")
        sandbox_manager.create_user_sandbox(admin_id)
        print(f"✅ تم إضافة الأدمن {admin_id}")
    
    # بدء مراقبة الموارد
    start_monitoring()
    print("✅ تم بدء مراقبة الموارد")
    
    # استعادة البوتات الشغالة
    restore_running_bots()
    
    # تنظيف الملفات القديمة
    cleanup_old_files()
    
    # جدولة التنظيف اليومي
    cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
    
    print("🤖 جاري تشغيل البوت...")
    
    # تشغيل البوت مع إعادة التشغيل التلقائي
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=60, skip_pending=True)
        except Exception as e:
            error_str = str(e)
            if "409" in error_str or "Conflict" in error_str:
                print("⚠️ خطأ 409: جاري إعادة المحاولة...")
                time.sleep(3)
            elif "Connection" in error_str or "Timeout" in error_str:
                print("⚠️ خطأ اتصال: جاري إعادة المحاولة...")
                time.sleep(5)
            else:
                print(f"❌ خطأ غير متوقع: {e}")
                logging.error(f"Bot error: {e}")
                time.sleep(10)