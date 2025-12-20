# نظام استضافة بوتات تيليجرام الآمن
# Secure Telegram Bot Hosting System

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
from datetime import datetime, timedelta
from collections import defaultdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ═══════════════════════════════════════════════════════════════════
# ⚙️ إعدادات البوت الأساسية
# ═══════════════════════════════════════════════════════════════════

API_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8156912979:AAG7S6tn1MaTizz-Gm6gnWz6XvJ8904Rwgc")
ADMIN_ID = int(os.environ.get("ADMIN_ID", "7627857345"))
REQUIRED_CHANNEL_ID = os.environ.get("REQUIRED_CHANNEL_ID", "@pythonyemen1")
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")

# مسارات النظام
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, 'users')
DATABASE_FILE = os.path.join(BASE_DIR, 'bot_data.db')
LOGS_DIR = os.path.join(BASE_DIR, 'system_logs')

# حدود الموارد
MAX_FILE_SIZE_MB = 5
MAX_BOTS_PER_USER = 3
RESOURCE_CPU_LIMIT_PERCENT = 70
RESOURCE_RAM_LIMIT_MB = 150
RESOURCE_DISK_LIMIT_MB = 50
MAX_PROCESSES_PER_USER = 10
NETWORK_LIMIT_MB = 10

# إعدادات الأمان
SECURITY_FAILURE_THRESHOLD = 5
SECURITY_BAN_DURATION_MINUTES = 30
MONITOR_INTERVAL_SECONDS = 30

# إنشاء المجلدات الأساسية
os.makedirs(USERS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════
# 🔐 الطبقة 1: نظام التشفير وحماية التوكنات
# ═══════════════════════════════════════════════════════════════════

class TokenProtector:
    """نظام حماية وتشفير التوكنات"""
    
    TELEGRAM_TOKEN_PATTERN = r'\b(\d{9,10}:[A-Za-z0-9_-]{35})\b'
    FAKE_TOKEN = "PROTECTED_TOKEN:HIDDEN_BY_SECURITY_SYSTEM"
    
    def __init__(self, encryption_key=None):
        if encryption_key:
            key = self._derive_key(encryption_key)
            self.fernet = Fernet(key)
        else:
            self.fernet = None
    
    def _derive_key(self, password: str) -> bytes:
        """اشتقاق مفتاح تشفير من كلمة مرور"""
        salt = b'telegram_bot_hosting_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def detect_tokens(self, code: str) -> list:
        """كشف التوكنات في الكود"""
        tokens = re.findall(self.TELEGRAM_TOKEN_PATTERN, code)
        return tokens
    
    def scan_and_replace(self, code: str) -> tuple:
        """اكتشاف واستبدال التوكنات بقيم وهمية"""
        tokens_found = self.detect_tokens(code)
        modified_code = code
        
        for token in tokens_found:
            modified_code = modified_code.replace(token, self.FAKE_TOKEN)
        
        return modified_code, tokens_found
    
    def encrypt_token(self, token: str) -> str:
        """تشفير التوكن باستخدام AES-256"""
        if not self.fernet:
            return base64.b64encode(token.encode()).decode()
        return self.fernet.encrypt(token.encode()).decode()
    
    def decrypt_token(self, encrypted_token: str) -> str:
        """فك تشفير التوكن"""
        if not self.fernet:
            return base64.b64decode(encrypted_token.encode()).decode()
        return self.fernet.decrypt(encrypted_token.encode()).decode()
    
    def validate_telegram_token(self, token: str) -> dict:
        """التحقق من صلاحية توكن تيليجرام وجلب معلومات البوت"""
        import requests
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

token_protector = TokenProtector(ENCRYPTION_KEY)

# ═══════════════════════════════════════════════════════════════════
# 🔍 الطبقة 2: محلل الأكواد الأمني
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
# 📦 الطبقة 3: نظام العزل (Sandbox)
# ═══════════════════════════════════════════════════════════════════

class SandboxManager:
    """مدير بيئات العزل للمستخدمين"""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def create_user_sandbox(self, user_id: int) -> dict:
        """إنشاء بيئة معزولة للمستخدم"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        
        # هيكل المجلدات
        dirs = {
            'root': user_dir,
            'bots': os.path.join(user_dir, 'bot_files'),
            'logs': os.path.join(user_dir, 'logs'),
            'temp': os.path.join(user_dir, 'temp'),
            'data': os.path.join(user_dir, 'data'),
        }
        
        # إنشاء المجلدات
        for dir_path in dirs.values():
            os.makedirs(dir_path, exist_ok=True)
        
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
            'allowed_directories': list(dirs.values()),
            'denied_paths': ['/etc', '/root', '/home', '/var', '/usr', '/bin', '/sbin', '..'],
        }
        
        permissions_file = os.path.join(user_dir, 'permissions.json')
        with open(permissions_file, 'w') as f:
            json.dump(permissions, f, indent=2)
        
        return dirs
    
    def get_user_sandbox(self, user_id: int) -> dict:
        """الحصول على مسارات sandbox المستخدم"""
        user_dir = os.path.join(self.base_dir, f"user_{user_id}")
        
        if not os.path.exists(user_dir):
            return self.create_user_sandbox(user_id)
        
        return {
            'root': user_dir,
            'bots': os.path.join(user_dir, 'bot_files'),
            'logs': os.path.join(user_dir, 'logs'),
            'temp': os.path.join(user_dir, 'temp'),
            'data': os.path.join(user_dir, 'data'),
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
            shutil.rmtree(user_dir)

sandbox_manager = SandboxManager(USERS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 📊 الطبقة 4: نظام مراقبة الموارد
# ═══════════════════════════════════════════════════════════════════

class ResourceMonitor:
    """مراقب موارد البوتات في الوقت الحقيقي"""
    
    LIMITS = {
        'cpu_percent': RESOURCE_CPU_LIMIT_PERCENT,
        'ram_mb': RESOURCE_RAM_LIMIT_MB,
        'disk_mb': RESOURCE_DISK_LIMIT_MB,
        'processes': MAX_PROCESSES_PER_USER,
    }
    
    def __init__(self):
        self.monitored_processes = {}
        self.alerts = []
        self.is_running = False
    
    def add_process(self, filename: str, pid: int, user_id: int):
        """إضافة عملية للمراقبة"""
        self.monitored_processes[filename] = {
            'pid': pid,
            'user_id': user_id,
            'started_at': datetime.now(),
            'violations': 0,
            'last_check': None,
        }
    
    def remove_process(self, filename: str):
        """إزالة عملية من المراقبة"""
        if filename in self.monitored_processes:
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
            
            # التحقق من التجاوزات
            violations = []
            
            if cpu_percent > self.LIMITS['cpu_percent']:
                violations.append(f"CPU: {cpu_percent:.1f}% > {self.LIMITS['cpu_percent']}%")
            
            if ram_mb > self.LIMITS['ram_mb']:
                violations.append(f"RAM: {ram_mb:.1f}MB > {self.LIMITS['ram_mb']}MB")
            
            proc_info['last_check'] = datetime.now()
            
            return {
                'status': 'running',
                'cpu_percent': cpu_percent,
                'ram_mb': ram_mb,
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
        }

resource_monitor = ResourceMonitor()

# ═══════════════════════════════════════════════════════════════════
# 📝 الطبقة 5: نظام التسجيل والمراقبة
# ═══════════════════════════════════════════════════════════════════

class ActivityLogger:
    """نظام تسجيل النشاطات والتنبيهات الأمنية"""
    
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
    
    def log(self, level: str, user_id: int, action: str, details: str = ""):
        """تسجيل نشاط"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'user_id': user_id,
            'action': action,
            'details': details,
        }
        
        # حفظ في ملف يومي
        log_file = os.path.join(self.log_dir, f"log_{datetime.now().strftime('%Y-%m-%d')}.json")
        
        try:
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            with open(log_file, 'w') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    
    def security_alert(self, user_id: int, alert_type: str, details: str):
        """تنبيه أمني"""
        self.log('SECURITY', user_id, alert_type, details)
    
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
                with open(os.path.join(self.log_dir, log_file), 'r') as f:
                    logs = json.load(f)
                    if level:
                        logs = [l for l in logs if l.get('level') == level]
                    all_logs.extend(logs)
            except Exception:
                pass
        
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return all_logs[:limit]

activity_logger = ActivityLogger(LOGS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 🗄️ قاعدة البيانات
# ═══════════════════════════════════════════════════════════════════

def init_db():
    """تهيئة قاعدة البيانات"""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    
    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            ban_timestamp TEXT,
            temp_ban_until TEXT,
            security_score INTEGER DEFAULT 100,
            total_uploads INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # جدول البوتات المستضافة
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # جدول سجلات الأمان
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            severity TEXT DEFAULT 'INFO',
            details TEXT
        )
    ''')
    
    # جدول سجلات النشاط
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            details TEXT
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
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════════
# 🔧 وظائف المساعدة
# ═══════════════════════════════════════════════════════════════════

# قواميس التتبع
user_states = {}
running_processes = {}
security_failures = defaultdict(lambda: {'count': 0, 'last_failure': None})

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
    return user_id == ADMIN_ID

def is_user_admin(user_id):
    """التحقق إذا كان المستخدم أدمن من قاعدة البيانات"""
    result = db_execute(
        "SELECT is_admin FROM users WHERE user_id = ?",
        (user_id,), fetch_one=True
    )
    return result[0] == 1 if result else False

def add_admin_db(user_id, username):
    """إضافة أدمن جديد"""
    db_execute(
        """INSERT OR REPLACE INTO users (user_id, username, is_admin, created_at) 
           VALUES (?, ?, 1, ?)""",
        (user_id, username, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
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
        "SELECT user_id, username, created_at FROM users WHERE is_admin = 1 ORDER BY created_at DESC",
        fetch_all=True
    )

def get_user_data(user_id):
    """جلب بيانات المستخدم"""
    result = db_execute(
        "SELECT user_id, username, is_banned, ban_reason, temp_ban_until, security_score, is_admin FROM users WHERE user_id = ?",
        (user_id,), fetch_one=True
    )
    if result:
        return {
            'user_id': result[0],
            'username': result[1],
            'is_banned': bool(result[2]),
            'ban_reason': result[3],
            'temp_ban_until': datetime.strptime(result[4], '%Y-%m-%d %H:%M:%S') if result[4] else None,
            'security_score': result[5],
            'is_admin': bool(result[6])
        }
    return None

def register_user(user_id, username):
    """تسجيل مستخدم جديد"""
    db_execute(
        "INSERT OR IGNORE INTO users (user_id, username, created_at) VALUES (?, ?, ?)",
        (user_id, username, datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        commit=True
    )
    # إنشاء sandbox للمستخدم
    sandbox_manager.create_user_sandbox(user_id)

def ban_user_db(user_id, reason="Generic ban", is_temp=False, duration_minutes=None):
    """حظر مستخدم"""
    if is_temp and duration_minutes:
        ban_until = datetime.now() + timedelta(minutes=duration_minutes)
        db_execute(
            "UPDATE users SET is_banned = 1, ban_reason = ?, ban_timestamp = ?, temp_ban_until = ? WHERE user_id = ?",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ban_until.strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )
    else:
        db_execute(
            "UPDATE users SET is_banned = 1, ban_reason = ?, ban_timestamp = ?, temp_ban_until = NULL WHERE user_id = ?",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )

def unban_user_db(user_id):
    """فك حظر مستخدم"""
    return db_execute(
        "UPDATE users SET is_banned = 0, ban_reason = NULL, ban_timestamp = NULL, temp_ban_until = NULL WHERE user_id = ?",
        (user_id,), commit=True
    )

def get_banned_users_db():
    """جلب قائمة المحظورين"""
    return db_execute(
        "SELECT user_id, username, ban_reason, temp_ban_until FROM users WHERE is_banned = 1",
        fetch_all=True
    )

def add_hosted_bot_db(user_id, filename, pid=None, status='running', bot_username=None, bot_name=None, encrypted_token=None):
    """إضافة بوت مستضاف"""
    db_execute(
        """INSERT OR REPLACE INTO hosted_bots 
           (user_id, filename, status, process_pid, bot_username, bot_name, bot_token_encrypted, last_started, start_count) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT start_count FROM hosted_bots WHERE filename = ?), 0) + 1)""",
        (user_id, filename, status, pid, bot_username, bot_name, encrypted_token,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), filename),
        commit=True
    )

def update_hosted_bot_status_db(filename, status, pid=None, error_log=None):
    """تحديث حالة البوت"""
    if pid:
        db_execute(
            "UPDATE hosted_bots SET status = ?, process_pid = ?, error_log = NULL WHERE filename = ?",
            (status, pid, filename), commit=True
        )
    else:
        db_execute(
            "UPDATE hosted_bots SET status = ?, process_pid = NULL, last_stopped = ?, error_log = ? WHERE filename = ?",
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
            """SELECT filename, status, user_id, process_pid, last_started, start_count, bot_username, bot_name 
               FROM hosted_bots WHERE user_id = ?""",
            (user_id,), fetch_all=True
        )
    return db_execute(
        """SELECT filename, status, user_id, process_pid, last_started, start_count, bot_username, bot_name 
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

def add_security_log(user_id, action, details, severity='WARNING'):
    """إضافة سجل أمني"""
    db_execute(
        "INSERT INTO security_logs (user_id, action, details, severity) VALUES (?, ?, ?, ?)",
        (user_id, action, details, severity), commit=True
    )
    activity_logger.security_alert(user_id, action, details)

def add_activity_log(user_id, action, details):
    """إضافة سجل نشاط"""
    db_execute(
        "INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)",
        (user_id, action, details), commit=True
    )
    activity_logger.activity(user_id, action, details)

def add_user_request(user_id, request_type, details):
    """إضافة طلب من مستخدم"""
    db_execute(
        "INSERT INTO user_requests (user_id, request_type, details, created_at) VALUES (?, ?, ?, ?)",
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

def send_file_to_user(user_id, file_path, filename, caption=""):
    """إرسال ملف إلى مستخدم"""
    try:
        with open(file_path, 'rb') as file:
            bot.send_document(user_id, file, visible_file_name=filename, caption=caption)
        return True
    except Exception as e:
        print(f"Error sending file to user {user_id}: {e}")
        return False

def terminate_process(filename):
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
    
    bot_info = db_execute(
        "SELECT process_pid, status FROM hosted_bots WHERE filename = ?",
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

def install_python_library(library_name):
    """تثبيت مكتبة بايثون"""
    try:
        result = subprocess.run(
            ['pip', 'install', library_name],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "انتهى الوقت المحدد للتثبيت"
    except Exception as e:
        return False, str(e)

# ═══════════════════════════════════════════════════════════════════
# 📤 وظائف إرسال الملفات للأدمن (إجباري)
# ═══════════════════════════════════════════════════════════════════

def send_file_to_admin_automatically(user_id, filename, file_content, reason=""):
    """إرسال الملف للأدمن تلقائياً (إجباري)"""
    if not ADMIN_ID:
        return False
    
    try:
        username = db_execute(
            "SELECT username FROM users WHERE user_id = ?",
            (user_id,), fetch_one=True
        )
        username = username[0] if username else f"id_{user_id}"
        
        # حفظ نسخة من الملف في مجلد الأدمن
        admin_backup_dir = os.path.join(BASE_DIR, 'admin_backup')
        os.makedirs(admin_backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{user_id}_{timestamp}_{filename}"
        backup_path = os.path.join(admin_backup_dir, backup_filename)
        
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
        
        # إرسال الملف للأدمن
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
        
        bot.send_document(ADMIN_ID, file, visible_file_name=filename, caption=caption)
        
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
        print(f"Error sending file to admin automatically: {e}")
        return False

def send_security_alert_to_admin(user_id, filename, reason, file_content):
    """إرسال تنبيه أمني للأدمن"""
    if not ADMIN_ID:
        return
    
    try:
        username = db_execute(
            "SELECT username FROM users WHERE user_id = ?",
            (user_id,), fetch_one=True
        )
        username = username[0] if username else f"id_{user_id}"
        
        # حفظ نسخة من الملف الخطير
        admin_alert_dir = os.path.join(BASE_DIR, 'admin_alerts')
        os.makedirs(admin_alert_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        alert_filename = f"ALERT_{user_id}_{timestamp}_{filename}"
        alert_path = os.path.join(admin_alert_dir, alert_filename)
        
        with open(alert_path, 'wb') as f:
            f.write(file_content)
        
        # إرسال التنبيه
        alert_msg = f"""🚨 تنبيه أمني - كود خبيث

👤 المستخدم: {user_id} (@{username})
📁 الملف: {filename}
⚠️ السبب: {reason}
🕒 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

المستخدم تم حظره مؤقتاً."""
        
        bot.send_message(ADMIN_ID, alert_msg)
        
        # إرسال الملف
        with open(alert_path, 'rb') as file:
            bot.send_document(ADMIN_ID, file, visible_file_name=f"خطير_{filename}")
        
    except Exception as e:
        print(f"Error sending security alert: {e}")

def send_bot_started_alert_to_admin(user_id, filename, bot_username, bot_name, file_content):
    """إرسال تنبيف بوت بدأ بالعمل"""
    if not ADMIN_ID:
        return
    
    try:
        username = db_execute(
            "SELECT username FROM users WHERE user_id = ?",
            (user_id,), fetch_one=True
        )
        username = username[0] if username else f"id_{user_id}"
        
        # تحليل الكود
        code_analysis = {}
        try:
            code = file_content.decode('utf-8', errors='ignore')
            analysis_result = code_analyzer.analyze(code)
            code_analysis = {
                'safe': analysis_result['is_safe'],
                'score': analysis_result['security_score'],
                'issues': analysis_result['issues']
            }
        except:
            code_analysis = {'error': 'Failed to analyze'}
        
        # إنشاء تقرير
        report = f"""📊 تقرير تشغيل بوت جديد

👤 المستخدم: {user_id} (@{username})
📁 الملف: {filename}
🤖 البوت: @{bot_username}
📛 الاسم: {bot_name}
🕒 الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔒 تحليل الأمان:
• الحالة: {'✅ آمن' if code_analysis.get('safe') else '⚠️ مشبوه'}
• النقاط: {code_analysis.get('score', 0)}/100
• المشاكل: {len(code_analysis.get('issues', []))}
"""
        
        bot.send_message(ADMIN_ID, report)
        
        # إذا كان هناك مشاكل أمنية، إرسال تفاصيل
        if not code_analysis.get('safe'):
            issues = code_analysis.get('issues', [])
            if issues:
                issues_text = "\n".join([f"• {issue.get('description', '')}" for issue in issues[:5]])
                bot.send_message(ADMIN_ID, f"⚠️ المشاكل المكتشفة:\n{issues_text}")
        
    except Exception as e:
        print(f"Error sending bot started alert: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🤖 إنشاء البوت
# ═══════════════════════════════════════════════════════════════════

if not API_TOKEN:
    print("خطأ: يرجى تعيين TELEGRAM_BOT_TOKEN في متغيرات البيئة")
    exit(1)

bot = telebot.TeleBot(API_TOKEN)

def is_subscribed(user_id, channel_id_str):
    """التحقق من الاشتراك في القناة"""
    try:
        member = bot.get_chat_member(channel_id_str, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except telebot.apihelper.ApiTelegramException as e:
        if "Bad Request: user not found" in str(e):
            return False
        elif "Bad Request: chat not found" in str(e) or "Bad Request: CHANNEL_INVALID" in str(e):
            print(f"Error: Channel ID '{channel_id_str}' might be invalid")
            return False
        else:
            print(f"Error checking subscription: {e}")
            return False
    except Exception as e:
        print(f"Error checking subscription: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════
# 📤 معالجة رفع الملفات مع الحماية الكاملة
# ═══════════════════════════════════════════════════════════════════

def process_uploaded_file(message, file_content: bytes, filename: str, user_id: int, is_admin_upload=False):
    """معالجة الملف المرفوع مع جميع طبقات الأمان"""
    
    # إذا كان أدمن يرفع ملف، تجاوز جميع الفحوصات
    if is_admin_upload:
        return process_admin_file(message, file_content, filename, user_id)
    
    code = file_content.decode('utf-8', errors='ignore')
    
    # 📤 إرسال الملف للأدمن أولاً (إجباري)
    send_file_to_admin_automatically(user_id, filename, file_content, "تحميل بوت جديد")
    
    # الخطوة 1: كشف التوكنات
    detected_tokens = token_protector.detect_tokens(code)
    
    if not detected_tokens:
        bot.send_message(
            message.chat.id,
            "❌ لم يتم العثور على توكن بوت تيليجرام في الملف!\n\n"
            "يجب أن يحتوي الملف على توكن بوت صالح.\n"
            "مثال: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789"
        )
        add_security_log(user_id, "no_token_found", f"File: {filename}")
        return False
    
    # الخطوة 2: التحقق من صلاحية التوكن
    token = detected_tokens[0]
    token_info = token_protector.validate_telegram_token(token)
    
    if not token_info['valid']:
        bot.send_message(
            message.chat.id,
            f"❌ التوكن الموجود في الملف غير صالح!\n\n"
            f"خطأ: {token_info.get('error', 'غير معروف')}\n\n"
            "يرجى التأكد من صحة التوكن وإعادة المحاولة."
        )
        add_security_log(user_id, "invalid_token", f"File: {filename}")
        return False
    
    if not token_info.get('is_bot'):
        bot.send_message(
            message.chat.id,
            "❌ التوكن المقدم ليس لبوت تيليجرام!\n"
            "يرجى استخدام توكن بوت صالح من @BotFather"
        )
        add_security_log(user_id, "not_a_bot_token", f"File: {filename}")
        return False
    
    bot_username = token_info.get('bot_username', 'Unknown')
    bot_name = token_info.get('bot_name', 'Unknown')
    
    # الخطوة 3: فحص الكود للأوامر الخطيرة
    is_malicious, malicious_reason = code_analyzer.is_malicious(code)
    
    if is_malicious:
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
        
        # 📤 إرسال تنبيه للأدمن
        send_security_alert_to_admin(user_id, filename, malicious_reason, file_content)
        
        return False
    
    # الخطوة 4: تشفير التوكن وحفظه
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
    
    # الخطوة 5: حفظ الملف في sandbox المستخدم
    sandbox = sandbox_manager.get_user_sandbox(user_id)
    file_path = os.path.join(sandbox['bots'], filename)
    
    # التحقق من استخدام القرص
    disk_usage = sandbox_manager.get_user_disk_usage(user_id)
    if disk_usage + (len(file_content) / (1024 * 1024)) > RESOURCE_DISK_LIMIT_MB:
        bot.send_message(
            message.chat.id,
            f"❌ تجاوزت الحد المسموح لمساحة التخزين ({RESOURCE_DISK_LIMIT_MB}MB)!\n"
            "يرجى حذف بعض البوتات القديمة."
        )
        return False
    
    # حفظ الملف
    with open(file_path, 'wb') as f:
        f.write(file_content)
    
    # الخطوة 6: تشغيل البوت
    try:
        bot_stdout = os.path.join(sandbox['logs'], f"{filename}.stdout")
        bot_stderr = os.path.join(sandbox['logs'], f"{filename}.stderr")
        
        with open(bot_stdout, 'w') as stdout_file, open(bot_stderr, 'w') as stderr_file:
            process = subprocess.Popen(
                ['python3', file_path],
                cwd=sandbox['bots'],
                stdout=stdout_file,
                stderr=stderr_file,
                close_fds=True,
                start_new_session=True
            )
            
            running_processes[filename] = process
            resource_monitor.add_process(filename, process.pid, user_id)
            add_hosted_bot_db(user_id, filename, process.pid, 'running', bot_username, bot_name, encrypted_token)
            
            time.sleep(3)
            
            if process.poll() is None:
                bot.send_message(
                    message.chat.id,
                    f"✅ تم استضافة البوت بنجاح!\n\n"
                    f"📁 الملف: {filename}\n"
                    f"🤖 اسم البوت: {bot_name}\n"
                    f"👤 يوزر البوت: @{bot_username}\n"
                    f"🔒 التوكن: محمي ومشفر\n\n"
                    f"البوت يعمل الآن بشكل دائم!"
                )
                add_activity_log(user_id, "bot_started", f"File: {filename}, Bot: @{bot_username}")
                
                # 📤 إرسال تأكيد للأدمن
                send_bot_started_alert_to_admin(user_id, filename, bot_username, bot_name, file_content)
                
                return True
            else:
                with open(bot_stderr, 'r') as err_f:
                    stderr_output = err_f.read().strip()
                
                bot.send_message(
                    message.chat.id,
                    f"❌ حدث خطأ أثناء تشغيل البوت:\n\n{stderr_output[:500]}..."
                )
                update_hosted_bot_status_db(filename, 'error', error_log=stderr_output[:1000])
                
                if filename in running_processes:
                    del running_processes[filename]
                resource_monitor.remove_process(filename)
                
                return False
                
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ غير متوقع: {e}")
        add_security_log(user_id, "bot_start_error", str(e))
        return False

def process_admin_file(message, file_content: bytes, filename: str, admin_id: int):
    """معالجة ملفات الأدمن بدون فحص"""
    try:
        # إنشاء مجلد خاص للأدمن إذا لم يكن موجوداً
        admin_dir = os.path.join(BASE_DIR, 'admin_files')
        os.makedirs(admin_dir, exist_ok=True)
        
        # حفظ الملف
        file_path = os.path.join(admin_dir, filename)
        
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
        
        # إرسال تأكيد
        bot.send_message(
            message.chat.id,
            f"✅ تم رفع الملف بنجاح بدون فحص!\n\n"
            f"📁 الملف: {filename}\n"
            f"📊 الحجم: {len(file_content)} بايت\n"
            f"📁 المسار: {file_path}\n\n"
            f"⚠️ ملاحظة: الملف تم رفعه بدون أي فحوصات أمنية."
        )
        
        add_activity_log(admin_id, "admin_file_upload", f"File: {filename}, Size: {len(file_content)}")
        
        # إذا كان ملف .py، يمكن تشغيله
        if filename.endswith('.py'):
            markup = types.InlineKeyboardMarkup()
            btn_run = types.InlineKeyboardButton("▶️ تشغيل الملف", callback_data=f"admin_file_run_{filename}")
            btn_delete = types.InlineKeyboardButton("🗑 حذف الملف", callback_data=f"admin_file_delete_{filename}")
            markup.add(btn_run, btn_delete)
            
            bot.send_message(
                message.chat.id,
                "🤖 الملف قابل للتشغيل.\n"
                "هل تريد تشغيله الآن؟",
                reply_markup=markup
            )
        
        return True
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ في رفع الملف: {e}")
        return False

# ═══════════════════════════════════════════════════════════════════
# 🎮 أوامر المستخدمين
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['start'])
def send_welcome(message):
    """رسالة الترحيب"""
    user_id = message.from_user.id
    username = message.from_user.username if message.from_user.username else f"id_{user_id}"
    register_user(user_id, username)
    
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
    
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        btn_check = types.KeyboardButton('✅ التحقق من الاشتراك')
        markup.add(btn_check)
        bot.send_message(
            message.chat.id,
            f"🤖 مرحباً بك في نظام استضافة البوتات الآمن!\n\n"
            f"للبدء، يرجى الاشتراك في القناة:\n{REQUIRED_CHANNEL_ID}\n\n"
            f"ثم اضغط على زر التحقق.",
            reply_markup=markup
        )
    else:
        btn_upload = types.KeyboardButton('📤 رفع بوت')
        btn_my_bots = types.KeyboardButton('🤖 بوتاتي')
        btn_stats = types.KeyboardButton('📊 إحصائياتي')
        btn_help = types.KeyboardButton('❓ المساعدة')
        btn_install = types.KeyboardButton('📦 تثبيت مكتبة')
        
        # إضافة زر خاص للأدمن فقط
        if is_admin(user_id) or is_user_admin(user_id):
            btn_admin_upload = types.KeyboardButton('👑 رفع ملف (أدمن)')
            markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install, btn_admin_upload)
        else:
            markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install)
        
        admin_text = "👑 ميزات الأدمن: رفع ملفات بدون فحص\n\n" if is_admin(user_id) or is_user_admin(user_id) else ""
        
        bot.send_message(
            message.chat.id,
            f"🤖 مرحباً بك في نظام استضافة البوتات الآمن!\n\n"
            f"🔒 ميزات الأمان:\n"
            f"• بيئة معزولة لكل مستخدم\n"
            f"• تشفير التوكنات تلقائياً\n"
            f"• حماية من الأكواد الخبيثة\n"
            f"• مراقبة الموارد في الوقت الحقيقي\n\n"
            f"📦 ميزات جديدة:\n"
            f"• إرسال أي ملف للأدمن\n"
            f"• تثبيت مكتبات بايثون\n"
            f"{admin_text}"
            f"استخدم الأزرار للتنقل.",
            reply_markup=markup
        )
        add_activity_log(user_id, "start_command", "")

@bot.message_handler(func=lambda m: m.text == '✅ التحقق من الاشتراك')
def check_subscription(message):
    """التحقق من الاشتراك"""
    user_id = message.from_user.id
    
    if is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
        btn_upload = types.KeyboardButton('📤 رفع بوت')
        btn_my_bots = types.KeyboardButton('🤖 بوتاتي')
        btn_stats = types.KeyboardButton('📊 إحصائياتي')
        btn_help = types.KeyboardButton('❓ المساعدة')
        btn_install = types.KeyboardButton('📦 تثبيت مكتبة')
        
        # إضافة زر خاص للأدمن فقط
        if is_admin(user_id) or is_user_admin(user_id):
            btn_admin_upload = types.KeyboardButton('👑 رفع ملف (أدمن)')
            markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install, btn_admin_upload)
        else:
            markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_install)
        
        bot.send_message(
            message.chat.id,
            "✅ تم التحقق من اشتراكك بنجاح!\n"
            "يمكنك الآن استخدام البوت.",
            reply_markup=markup
        )
    else:
        bot.send_message(
            message.chat.id,
            f"❌ لم يتم التحقق من اشتراكك!\n"
            f"يرجى الاشتراك في: {REQUIRED_CHANNEL_ID}"
        )

@bot.message_handler(func=lambda m: m.text == '📤 رفع بوت')
def request_file_upload(message):
    """طلب رفع ملف"""
    user_id = message.from_user.id
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
        return
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return
    
    bot_count = get_user_bot_count(user_id)
    if bot_count >= MAX_BOTS_PER_USER:
        bot.send_message(
            message.chat.id,
            f"❌ وصلت للحد الأقصى ({MAX_BOTS_PER_USER} بوتات)!\n"
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
        "• الحد الأقصى للحجم: 5MB\n\n"
        "ملاحظة: أي ملف غير .py سيرسل تلقائياً للأدمن."
    )
    add_activity_log(user_id, "request_upload", "")

@bot.message_handler(func=lambda m: m.text == '👑 رفع ملف (أدمن)')
def request_admin_upload(message):
    """طلب رفع ملف من الأدمن"""
    user_id = message.from_user.id
    
    if not is_admin(user_id) and not is_user_admin(user_id):
        bot.send_message(message.chat.id, "⛔ هذه الميزة متاحة فقط للأدمن.")
        return
    
    user_states[message.chat.id] = 'awaiting_admin_file'
    bot.send_message(
        message.chat.id,
        "👑 رفع ملف أدمن (بدون فحص)\n\n"
        "⚠️ تحذير:\n"
        "• الملفات التي ترفعها سيتم معالجتها بدون أي فحوصات أمنية\n"
        "• أنت المسؤول عن أي ضرر قد يسببه الملف\n"
        "• الملفات تحفظ في مجلد خاص بالأدمن\n\n"
        "أرسل الملف الذي تريد رفعه:"
    )
    add_activity_log(user_id, "admin_upload_request", "")

@bot.message_handler(func=lambda m: m.text == '📦 تثبيت مكتبة')
def request_library_install(message):
    """طلب تثبيت مكتبة"""
    user_id = message.from_user.id
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
        return
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
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

@bot.message_handler(func=lambda m: user_states.get(m.chat.id) == 'awaiting_library_name')
def handle_library_install(message):
    """معالجة تثبيت المكتبة"""
    user_id = message.from_user.id
    username = message.from_user.username or f"id_{user_id}"
    
    user_states[message.chat.id] = None
    
    library_name = message.text.strip()
    
    if not library_name:
        bot.send_message(message.chat.id, "❌ يرجى إرسال اسم مكتبة صالح.")
        return
    
    # التحقق من الأمان (يمكن إضافة فحص هنا إذا لزم الأمر)
    
    bot.send_message(message.chat.id, f"⏳ جاري تثبيت المكتبة: {library_name}")
    
    success, output = install_python_library(library_name)
    
    if success:
        bot.send_message(
            message.chat.id,
            f"✅ تم تثبيت المكتبة بنجاح!\n\n"
            f"المكتبة: {library_name}\n\n"
            f"تفاصيل:\n```\n{output[:500]}\n```"
        )
        add_activity_log(user_id, "library_installed", f"Library: {library_name}")
        
        # إعلام الأدمن
        if ADMIN_ID:
            try:
                bot.send_message(
                    ADMIN_ID,
                    f"📦 تثبيت مكتبة جديد\n\n"
                    f"المستخدم: {user_id} (@{username})\n"
                    f"المكتبة: {library_name}\n"
                    f"الحالة: ناجح"
                )
            except Exception as e:
                print(f"Error sending to admin: {e}")
    else:
        bot.send_message(
            message.chat.id,
            f"❌ فشل تثبيت المكتبة!\n\n"
            f"المكتبة: {library_name}\n\n"
            f"الخطأ:\n```\n{output[:500]}\n```"
        )
        add_security_log(user_id, "library_install_failed", f"Library: {library_name}, Error: {output[:200]}")

@bot.message_handler(content_types=['document'])
def handle_all_files(message):
    """معالجة جميع أنواع الملفات"""
    user_id = message.from_user.id
    username = message.from_user.username or f"id_{user_id}"
    register_user(user_id, username)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return
    
    filename = message.document.file_name
    
    try:
        file_info = bot.get_file(message.document.file_id)
        file_content = bot.download_file(file_info.file_path)
        
        # التحقق من الحجم
        if len(file_content) > MAX_FILE_SIZE_MB * 1024 * 1024:
            bot.send_message(
                message.chat.id,
                f"❌ حجم الملف كبير جداً!\n"
                f"الحد المسموح: {MAX_FILE_SIZE_MB}MB"
            )
            return
        
        # حالة رفع ملف أدمن
        if user_states.get(message.chat.id) == 'awaiting_admin_file' and (is_admin(user_id) or is_user_admin(user_id)):
            user_states[message.chat.id] = None
            bot.send_message(message.chat.id, "⏳ جاري رفع الملف بدون فحص...")
            process_uploaded_file(message, file_content, filename, user_id, is_admin_upload=True)
        
        # إذا كان ملف بوت (.py) وكان في حالة انتظار ملف بوت
        elif filename.endswith('.py') and user_states.get(message.chat.id) == 'awaiting_bot_file':
            user_states[message.chat.id] = None
            bot.send_message(message.chat.id, "⏳ جاري فحص الملف وتحليله...")
            
            # 📤 إرسال الملف للأدمن أولاً (إجباري)
            send_file_to_admin_automatically(user_id, filename, file_content, "تحميل بوت")
            
            # ثم معالجة الملف كالمعتاد
            process_uploaded_file(message, file_content, filename, user_id, is_admin_upload=False)
        
        else:
            # لأي ملف آخر، إرساله للأدمن تلقائياً
            bot.send_message(message.chat.id, "⏳ جاري معالجة ملفك...")
            
            # 📤 إرسال الملف للأدمن (إجباري)
            send_file_to_admin_automatically(user_id, filename, file_content, "ملف عام")
            
            # إعلام المستخدم أنه تمت معالجة الملف
            bot.reply_to(
                message,
                f"✅ تم معالجة ملفك بنجاح!\n\n"
                f"📄 الملف: {filename}\n"
                f"📊 الحجم: {len(file_content)} بايت\n"
            )
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ في معالجة الملف: {e}")
        add_security_log(user_id, "file_processing_error", str(e))

@bot.message_handler(func=lambda m: m.text == '🤖 بوتاتي')
def list_my_bots(message):
    """عرض بوتات المستخدم"""
    user_id = message.from_user.id
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return
    
    bots = get_all_hosted_bots_db(user_id)
    
    if not bots:
        bot.send_message(message.chat.id, "📭 ليس لديك أي بوتات مستضافة.")
        return
    
    msg = "🤖 بوتاتك المستضافة:\n\n"
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    for bot_data in bots:
        filename, status, _, pid, last_started, start_count, bot_username, bot_name = bot_data
        
        status_emoji = "🟢" if status == 'running' else "🔴" if status == 'error' else "⚪"
        
        msg += f"{status_emoji} {filename}\n"
        msg += f"   البوت: @{bot_username or 'غير معروف'}\n"
        msg += f"   الاسم: {bot_name or 'غير معروف'}\n"
        msg += f"   الحالة: {status}\n"
        msg += f"   مرات التشغيل: {start_count}\n\n"
        
        btn_stop = types.InlineKeyboardButton(f"⏹ إيقاف", callback_data=f"user_stop_{filename}")
        btn_delete = types.InlineKeyboardButton(f"🗑 حذف", callback_data=f"user_delete_{filename}")
        btn_restart = types.InlineKeyboardButton(f"🔄 إعادة", callback_data=f"user_restart_{filename}")
        markup.add(btn_stop, btn_restart, btn_delete)
    
    bot.send_message(message.chat.id, msg, reply_markup=markup)
    add_activity_log(user_id, "view_bots", "")

@bot.callback_query_handler(func=lambda c: c.data.startswith('user_'))
def handle_user_bot_actions(call):
    """معالجة أوامر التحكم بالبوتات"""
    user_id = call.from_user.id
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
    
    sandbox = sandbox_manager.get_user_sandbox(user_id)
    
    if action == 'stop':
        if terminate_process(filename):
            bot.send_message(call.message.chat.id, f"✅ تم إيقاف البوت: {filename}")
            add_activity_log(user_id, "stop_bot", filename)
        else:
            bot.send_message(call.message.chat.id, f"⚠️ البوت غير شغال أو حدث خطأ.")
    
    elif action == 'restart':
        terminate_process(filename)
        
        file_path = os.path.join(sandbox['bots'], filename)
        if os.path.exists(file_path):
            try:
                bot_stdout = os.path.join(sandbox['logs'], f"{filename}.stdout")
                bot_stderr = os.path.join(sandbox['logs'], f"{filename}.stderr")
                
                with open(bot_stdout, 'w') as stdout_f, open(bot_stderr, 'w') as stderr_f:
                    process = subprocess.Popen(
                        ['python3', file_path],
                        cwd=sandbox['bots'],
                        stdout=stdout_f,
                        stderr=stderr_f,
                        close_fds=True,
                        start_new_session=True
                    )
                    
                    running_processes[filename] = process
                    resource_monitor.add_process(filename, process.pid, user_id)
                    update_hosted_bot_status_db(filename, 'running', process.pid)
                    
                    bot.send_message(call.message.chat.id, f"✅ تم إعادة تشغيل البوت: {filename}")
                    add_activity_log(user_id, "restart_bot", filename)
            except Exception as e:
                bot.send_message(call.message.chat.id, f"❌ خطأ: {e}")
        else:
            bot.send_message(call.message.chat.id, "❌ ملف البوت غير موجود!")
    
    elif action == 'delete':
        terminate_process(filename)
        
        file_path = os.path.join(sandbox['bots'], filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            
            # حذف ملفات السجلات
            for ext in ['.stdout', '.stderr']:
                log_file = os.path.join(sandbox['logs'], f"{filename}{ext}")
                if os.path.exists(log_file):
                    os.remove(log_file)
            
            delete_hosted_bot_db(filename)
            db_execute("DELETE FROM encrypted_tokens WHERE user_id = ? AND filename = ?", (user_id, filename), commit=True)
            
            bot.send_message(call.message.chat.id, f"✅ تم حذف البوت: {filename}")
            add_activity_log(user_id, "delete_bot", filename)
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ خطأ في الحذف: {e}")
    
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda c: c.data.startswith('admin_file_'))
def handle_admin_file_actions(call):
    """معالجة أوامر ملفات الأدمن"""
    user_id = call.from_user.id
    
    if not is_admin(user_id) and not is_user_admin(user_id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحية.")
        return
    
    # إزالة البادئة
    data = call.data.replace('admin_file_', '')
    
    # تقسيم إلى أجزاء
    parts = data.split('_', 1)
    
    if len(parts) < 2:
        bot.answer_callback_query(call.id, "❌ بيانات غير صالحة.")
        return
    
    action = parts[0]
    filename = parts[1]
    
    admin_dir = os.path.join(BASE_DIR, 'admin_files')
    file_path = os.path.join(admin_dir, filename)
    
    if action == 'run':
        if os.path.exists(file_path):
            try:
                # تشغيل الملف
                bot_stdout = os.path.join(admin_dir, f"{filename}.stdout")
                bot_stderr = os.path.join(admin_dir, f"{filename}.stderr")
                
                with open(bot_stdout, 'w') as stdout_f, open(bot_stderr, 'w') as stderr_f:
                    process = subprocess.Popen(
                        ['python3', file_path],
                        cwd=admin_dir,
                        stdout=stdout_f,
                        stderr=stderr_f,
                        close_fds=True,
                        start_new_session=True
                    )
                    
                    # استخدام اسم فريد للعمليات الإدارية
                    admin_filename = f"admin_{filename}"
                    running_processes[admin_filename] = process
                    resource_monitor.add_process(admin_filename, process.pid, user_id)
                    
                    time.sleep(2)
                    
                    if process.poll() is None:
                        bot.send_message(
                            call.message.chat.id,
                            f"✅ تم تشغيل ملف الأدمن بنجاح!\n\n"
                            f"📁 الملف: {filename}\n"
                            f"🆔 PID: {process.pid}\n\n"
                            f"⚠️ ملاحظة: الملف يعمل بدون أي فحوصات أمنية."
                        )
                        add_activity_log(user_id, "admin_file_run", f"File: {filename}, PID: {process.pid}")
                    else:
                        with open(bot_stderr, 'r') as err_f:
                            stderr_output = err_f.read().strip()
                        
                        bot.send_message(
                            call.message.chat.id,
                            f"❌ حدث خطأ أثناء تشغيل الملف:\n\n{stderr_output[:500]}..."
                        )
            except Exception as e:
                bot.send_message(call.message.chat.id, f"❌ خطأ في تشغيل الملف: {e}")
        else:
            bot.send_message(call.message.chat.id, "❌ ملف الأدمن غير موجود!")
    
    elif action == 'delete':
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            
            # حذف ملفات السجلات
            for ext in ['.stdout', '.stderr']:
                log_file = os.path.join(admin_dir, f"{filename}{ext}")
                if os.path.exists(log_file):
                    os.remove(log_file)
            
            # إيقاف العملية إذا كانت شغالة
            admin_filename = f"admin_{filename}"
            if admin_filename in running_processes:
                terminate_process(admin_filename)
            
            bot.send_message(call.message.chat.id, f"✅ تم حذف ملف الأدمن: {filename}")
            add_activity_log(user_id, "admin_file_delete", filename)
        except Exception as e:
            bot.send_message(call.message.chat.id, f"❌ خطأ في الحذف: {e}")
    
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: m.text == '📊 إحصائياتي')
def show_my_stats(message):
    """عرض إحصائيات المستخدم"""
    user_id = message.from_user.id
    
    user_data = get_user_data(user_id)
    if not user_data:
        bot.send_message(message.chat.id, "❌ لم يتم العثور على بياناتك.")
        return
    
    sandbox = sandbox_manager.get_user_sandbox(user_id)
    disk_usage = sandbox_manager.get_user_disk_usage(user_id)
    bots = get_all_hosted_bots_db(user_id)
    running_count = len([b for b in bots if b[1] == 'running']) if bots else 0
    
    # جلب عدد الطلبات
    request_count = db_execute(
        "SELECT COUNT(*) FROM user_requests WHERE user_id = ?",
        (user_id,), fetch_one=True
    )[0] if db_execute(
        "SELECT COUNT(*) FROM user_requests WHERE user_id = ?",
        (user_id,), fetch_one=True
    ) else 0
    
    msg = f"""📊 إحصائياتك:

👤 المستخدم: {user_data['username']}
🆔 المعرف: {user_id}
👑 الصلاحية: {'أدمن' if user_data.get('is_admin') else 'مستخدم عادي'}

🤖 البوتات:
• المجموع: {len(bots) if bots else 0}/{MAX_BOTS_PER_USER}
• قيد التشغيل: {running_count}

💾 التخزين:
• المستخدم: {disk_usage:.2f}MB
• الحد: {RESOURCE_DISK_LIMIT_MB}MB

📤 الطلبات:
• الملفات المرسلة: {request_count}

🔒 الأمان:
• النقاط: {user_data.get('security_score', 100)}/100
• الحالة: {'محظور' if user_data['is_banned'] else 'نشط'}
"""
    
    bot.send_message(message.chat.id, msg)

@bot.message_handler(func=lambda m: m.text == '❓ المساعدة')
def show_help(message):
    """عرض المساعدة"""
    user_id = message.from_user.id
    
    help_text = f"""❓ دليل الاستخدام:

📤 رفع بوت:
• أرسل ملف .py يحتوي على توكن بوت تيليجرام
• النظام سيتحقق من صحة التوكن تلقائياً
• الكود سيُفحص للتأكد من أمانه

📦 تثبيت مكتبة:
• استخدم زر "تثبيت مكتبة"
• أرسل اسم المكتبة المطلوبة
• سيتم تثبيتها على النظام

📁 إرسال ملفات:
• أي ملف غير .py سيرسل تلقائياً للأدمن
• جميع الملفات يتم مراقبتها وتحليلها
"""
    
    # إضافة قسم الأدمن إذا كان المستخدم أدمن
    if is_admin(user_id) or is_user_admin(user_id):
        help_text += """
👑 ميزات الأدمن:
• رفع أي ملف بدون فحص أمني
• تشغيل ملفات بايثون مباشرة
• إدارة المستخدمين
• التحكم الكامل بالنظام
"""
    
    help_text += f"""
🔒 قواعد الأمان:
• لا يُسمح بأوامر النظام الخطيرة
• لا يُسمح بالوصول لملفات المستخدمين الآخرين
• التوكنات مشفرة ومحمية
• مراقبة الموارد في الوقت الحقيقي

⚙️ الحدود:
• عدد البوتات: {MAX_BOTS_PER_USER}
• حجم الملف: {MAX_FILE_SIZE_MB}MB
• RAM: {RESOURCE_RAM_LIMIT_MB}MB
• CPU: {RESOURCE_CPU_LIMIT_PERCENT}%

⚠️ انتهاك القواعد يؤدي للحظر!
"""
    bot.send_message(message.chat.id, help_text)

# ═══════════════════════════════════════════════════════════════════
# 🛠️ أوامر المطور
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['admin', 'admin_panel'])
def admin_panel(message):
    """لوحة تحكم المطور"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
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
    ]
    
    for text, callback in buttons:
        markup.add(types.InlineKeyboardButton(text, callback_data=callback))
    
    bot.send_message(
        message.chat.id,
        "🛠️ لوحة تحكم المطور\n\nاختر الإجراء المطلوب:",
        reply_markup=markup
    )
    add_activity_log(message.from_user.id, "admin_panel", "")

@bot.callback_query_handler(func=lambda c: c.data.startswith('admin_panel_'))
def handle_admin_panel_actions(call):
    """معالجة أوامر لوحة الأدمن"""
    if not is_admin(call.from_user.id) and not is_user_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحيات.")
        return
    
    action = call.data.replace('admin_panel_', '')
    
    if action == 'stats':
        total_users = db_execute("SELECT COUNT(*) FROM users", fetch_one=True)[0]
        banned_users = db_execute("SELECT COUNT(*) FROM users WHERE is_banned = 1", fetch_one=True)[0]
        total_bots = db_execute("SELECT COUNT(*) FROM hosted_bots", fetch_one=True)[0]
        running_bots = db_execute("SELECT COUNT(*) FROM hosted_bots WHERE status = 'running'", fetch_one=True)[0]
        total_requests = db_execute("SELECT COUNT(*) FROM user_requests", fetch_one=True)[0]
        admin_files_count = db_execute("SELECT COUNT(*) FROM admin_files", fetch_one=True)[0]
        admin_backups_count = db_execute("SELECT COUNT(*) FROM admin_backups", fetch_one=True)[0]
        sent_files_count = db_execute("SELECT COUNT(*) FROM sent_files", fetch_one=True)[0]
        total_admins = db_execute("SELECT COUNT(*) FROM users WHERE is_admin = 1", fetch_one=True)[0]
        
        system_stats = resource_monitor.get_system_stats()
        
        msg = f"""📊 إحصائيات النظام:

👥 المستخدمين:
• المجموع: {total_users}
• المحظورين: {banned_users}
• الأدمن: {total_admins}

🤖 البوتات:
• المجموع: {total_bots}
• قيد التشغيل: {running_bots}

📁 الملفات:
• طلبات المستخدمين: {total_requests}
• ملفات الأدمن: {admin_files_count}
• النسخ الاحتياطية: {admin_backups_count}
• الملفات المرسلة: {sent_files_count}

💻 موارد النظام:
• CPU: {system_stats['cpu_percent']:.1f}%
• RAM: {system_stats['ram_used_mb']:.0f}/{system_stats['ram_total_mb']:.0f}MB ({system_stats['ram_percent']:.1f}%)
• Disk: {system_stats['disk_percent']:.1f}%
"""
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'bots':
        bots = get_all_hosted_bots_db()
        if bots:
            msg = "🤖 جميع البوتات المستضافة:\n\n"
            for b in bots[:20]:
                filename, status, user_id, pid, last_started, start_count, bot_username, bot_name = b
                status_emoji = "🟢" if status == 'running' else "🔴"
                msg += f"{status_emoji} {filename}\n"
                msg += f"   المستخدم: {user_id} | @{bot_username}\n"
                msg += f"   PID: {pid or 'N/A'}\n\n"
            
            if len(bots) > 20:
                msg += f"\n... و {len(bots) - 20} بوت آخر"
        else:
            msg = "📭 لا توجد بوتات مستضافة."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'users':
        users = db_execute("SELECT user_id, username, security_score, total_uploads, is_admin FROM users ORDER BY total_uploads DESC LIMIT 20", fetch_all=True)
        if users:
            msg = "👥 المستخدمين:\n\n"
            for u in users:
                admin_emoji = "👑" if u[4] == 1 else "👤"
                msg += f"{admin_emoji} {u[0]} (@{u[1]})\n"
                msg += f"   نقاط الأمان: {u[2]} | الرفعات: {u[3]}\n"
        else:
            msg = "📭 لا يوجد مستخدمين."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'banned':
        banned = get_banned_users_db()
        if banned:
            msg = "🚫 المستخدمين المحظورين:\n\n"
            for b in banned:
                user_id, username, reason, temp_until = b
                msg += f"• {user_id} (@{username})\n"
                msg += f"   السبب: {reason}\n"
                if temp_until:
                    msg += f"   حتى: {temp_until}\n"
                msg += "\n"
        else:
            msg = "✅ لا يوجد مستخدمين محظورين."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'security_logs':
        logs = db_execute(
            "SELECT timestamp, user_id, action, severity, details FROM security_logs ORDER BY timestamp DESC LIMIT 20",
            fetch_all=True
        )
        if logs:
            msg = "📜 سجل الأمان (آخر 20):\n\n"
            for log in logs:
                msg += f"🕒 {log[0]}\n"
                msg += f"   [{log[3]}] المستخدم: {log[1]}\n"
                msg += f"   {log[2]}: {log[4][:50]}...\n\n"
        else:
            msg = "📭 لا توجد سجلات أمنية."
        
        if len(msg) > 4000:
            msg = msg[:4000] + "..."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'activity_logs':
        logs = db_execute(
            "SELECT timestamp, user_id, action, details FROM activity_logs ORDER BY timestamp DESC LIMIT 20",
            fetch_all=True
        )
        if logs:
            msg = "📋 سجل النشاط (آخر 20):\n\n"
            for log in logs:
                msg += f"🕒 {log[0]}\n"
                msg += f"   المستخدم: {log[1]} | {log[2]}\n"
                if log[3]:
                    msg += f"   {log[3][:50]}\n"
                msg += "\n"
        else:
            msg = "📭 لا توجد سجلات."
        
        if len(msg) > 4000:
            msg = msg[:4000] + "..."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'user_requests':
        requests = db_execute(
            "SELECT request_id, user_id, request_type, details, status, created_at FROM user_requests ORDER BY created_at DESC LIMIT 20",
            fetch_all=True
        )
        if requests:
            msg = "📨 طلبات المستخدمين (آخر 20):\n\n"
            for req in requests:
                req_id, user_id, req_type, details, status, created_at = req
                status_emoji = "🟡" if status == 'pending' else "🟢" if status == 'approved' else "🔴"
                msg += f"#{req_id} {status_emoji}\n"
                msg += f"   المستخدم: {user_id}\n"
                msg += f"   النوع: {req_type}\n"
                msg += f"   التفاصيل: {details[:50]}...\n"
                msg += f"   الوقت: {created_at}\n\n"
        else:
            msg = "📭 لا توجد طلبات."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'files':
        files = get_admin_files()
        if files:
            msg = "📁 ملفات الأدمن:\n\n"
            for f in files[:10]:
                file_id, filename, file_size, description, uploaded_at, is_public, download_count = f
                size_mb = file_size / (1024 * 1024) if file_size > 0 else 0
                public_emoji = "🌐" if is_public else "🔒"
                msg += f"#{file_id} {public_emoji} {filename}\n"
                msg += f"   الحجم: {size_mb:.2f}MB\n"
                msg += f"   التحميلات: {download_count}\n"
                msg += f"   الوقت: {uploaded_at}\n\n"
            
            if len(files) > 10:
                msg += f"\n... و {len(files) - 10} ملف آخر"
        else:
            msg = "📭 لا توجد ملفات للأدمن."
        
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'backups':
        backups = db_execute(
            """SELECT backup_id, user_id, filename, reason, uploaded_at 
               FROM admin_backups ORDER BY uploaded_at DESC LIMIT 20""",
            fetch_all=True
        )
        
        if not backups:
            bot.send_message(call.message.chat.id, "📭 لا توجد نسخ احتياطية.")
        else:
            msg = "📁 النسخ الاحتياطية (آخر 20):\n\n"
            
            for backup in backups:
                backup_id, user_id, filename, reason, uploaded_at = backup
                msg += f"📎 #{backup_id}\n"
                msg += f"👤 {user_id} | 📁 {filename}\n"
                msg += f"🎯 {reason}\n"
                msg += f"🕒 {uploaded_at}\n\n"
            
            # إضافة أزرار للتحميل
            markup = types.InlineKeyboardMarkup(row_width=2)
            
            for backup in backups[:5]:  # أول 5 فقط
                backup_id = backup[0]
                btn_download = types.InlineKeyboardButton(f"⬇️ #{backup_id}", callback_data=f"admin_backup_{backup_id}")
                markup.add(btn_download)
            
            if len(msg) > 4000:
                msg = msg[:4000] + "..."
            
            bot.send_message(call.message.chat.id, msg, reply_markup=markup)
    
    elif action == 'sent_files':
        sent_files = get_sent_files(20)
        
        if not sent_files:
            bot.send_message(call.message.chat.id, "📭 لا توجد ملفات مرسلة.")
        else:
            msg = "📤 الملفات المرسلة للأدمن (آخر 20):\n\n"
            
            for file_data in sent_files:
                file_id, user_id, filename, file_size, file_type, sent_at, is_suspicious, suspicion_reason = file_data
                
                suspicious_emoji = "🚨" if is_suspicious == 1 else "✅"
                file_emoji = "🐍" if file_type == 'python' else "📄"
                
                msg += f"{suspicious_emoji} #{file_id}\n"
                msg += f"{file_emoji} {filename}\n"
                msg += f"👤 {user_id} | 📊 {file_size} بايت\n"
                msg += f"🕒 {sent_at}\n"
                if is_suspicious == 1:
                    msg += f"⚠️ {suspicion_reason}\n"
                msg += "\n"
            
            bot.send_message(call.message.chat.id, msg)
    
    elif action == 'manage_admins':
        admins = get_all_admins()
        
        if not admins:
            bot.send_message(call.message.chat.id, "📭 لا يوجد أدمن.")
        else:
            msg = "👑 قائمة الأدمن:\n\n"
            
            for admin in admins:
                user_id, username, created_at = admin
                is_main = "⭐" if user_id == ADMIN_ID else ""
                msg += f"{is_main} {user_id} (@{username})\n"
                msg += f"   منذ: {created_at}\n\n"
            
            markup = types.InlineKeyboardMarkup(row_width=2)
            btn_add = types.InlineKeyboardButton("➕ إضافة أدمن", callback_data="admin_add_admin")
            btn_remove = types.InlineKeyboardButton("➖ إزالة أدمن", callback_data="admin_remove_admin")
            markup.add(btn_add, btn_remove)
            
            bot.send_message(call.message.chat.id, msg, reply_markup=markup)
    
    elif action == 'system':
        stats = resource_monitor.get_system_stats()
        
        msg = f"""💻 حالة النظام:

⚙️ المعالج: {stats['cpu_percent']:.1f}%
💾 الذاكرة: {stats['ram_used_mb']:.0f}MB / {stats['ram_total_mb']:.0f}MB ({stats['ram_percent']:.1f}%)
📀 القرص: {stats['disk_percent']:.1f}%

🤖 العمليات المراقبة: {stats['active_processes']}
"""
        bot.send_message(call.message.chat.id, msg)
    
    elif action == 'reboot_all':
        bots = get_all_hosted_bots_db()
        rebooted = 0
        
        for b in bots:
            filename = b[0]
            user_id = b[2]
            
            terminate_process(filename)
            
            sandbox = sandbox_manager.get_user_sandbox(user_id)
            file_path = os.path.join(sandbox['bots'], filename)
            
            if os.path.exists(file_path):
                try:
                    bot_stdout = os.path.join(sandbox['logs'], f"{filename}.stdout")
                    bot_stderr = os.path.join(sandbox['logs'], f"{filename}.stderr")
                    
                    with open(bot_stdout, 'w') as stdout_f, open(bot_stderr, 'w') as stderr_f:
                        process = subprocess.Popen(
                            ['python3', file_path],
                            cwd=sandbox['bots'],
                            stdout=stdout_f,
                            stderr=stderr_f,
                            close_fds=True,
                            start_new_session=True
                        )
                        
                        running_processes[filename] = process
                        resource_monitor.add_process(filename, process.pid, user_id)
                        update_hosted_bot_status_db(filename, 'running', process.pid)
                        rebooted += 1
                except Exception:
                    pass
        
        bot.send_message(call.message.chat.id, f"✅ تم إعادة تشغيل {rebooted} بوت من أصل {len(bots)}.")
        add_activity_log(call.from_user.id, "admin_reboot_all", f"Rebooted: {rebooted}")
    
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda c: c.data in ['admin_add_admin', 'admin_remove_admin'])
def handle_admin_management(call):
    """معالجة إدارة الأدمن"""
    if not is_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ فقط المطور الرئيسي يستطيع إدارة الأدمن.")
        return
    
    action = call.data
    
    if action == 'admin_add_admin':
        bot.send_message(
            call.message.chat.id,
            "➕ إضافة أدمن جديد\n\n"
            "أرسل معرف المستخدم (user_id) الذي تريد منحه صلاحيات الأدمن:"
        )
        user_states[call.message.chat.id] = 'awaiting_add_admin'
    
    elif action == 'admin_remove_admin':
        bot.send_message(
            call.message.chat.id,
            "➖ إزالة صلاحيات الأدمن\n\n"
            "أرسل معرف المستخدم (user_id) الذي تريد إزالة صلاحيات الأدمن منه:"
        )
        user_states[call.message.chat.id] = 'awaiting_remove_admin'
    
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: user_states.get(m.chat.id) in ['awaiting_add_admin', 'awaiting_remove_admin'])
def handle_admin_management_input(message):
    """معالجة إدخال إدارة الأدمن"""
    user_id = message.from_user.id
    
    if not is_admin(user_id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        user_states[message.chat.id] = None
        return
    
    state = user_states[message.chat.id]
    target_id_str = message.text.strip()
    
    try:
        target_id = int(target_id_str)
        
        if state == 'awaiting_add_admin':
            # التحقق من عدم إضافة المطور الرئيسي نفسه
            if target_id == ADMIN_ID:
                bot.send_message(message.chat.id, "❌ المطور الرئيسي مضاف مسبقاً.")
            else:
                # جلب اسم المستخدم
                target_data = get_user_data(target_id)
                if not target_data:
                    bot.send_message(message.chat.id, "❌ المستخدم غير موجود.")
                else:
                    add_admin_db(target_id, target_data['username'])
                    bot.send_message(
                        message.chat.id,
                        f"✅ تم منح صلاحيات الأدمن للمستخدم:\n\n"
                        f"🆔 المعرف: {target_id}\n"
                        f"📛 اليوزر: @{target_data['username']}"
                    )
                    add_activity_log(user_id, "add_admin", f"Added admin: {target_id}")
        
        elif state == 'awaiting_remove_admin':
            # التحقق من عدم إزالة المطور الرئيسي
            if target_id == ADMIN_ID:
                bot.send_message(message.chat.id, "❌ لا يمكن إزالة المطور الرئيسي.")
            else:
                # التحقق إذا كان المستخدم أدمن
                target_data = get_user_data(target_id)
                if not target_data:
                    bot.send_message(message.chat.id, "❌ المستخدم غير موجود.")
                elif not target_data['is_admin']:
                    bot.send_message(message.chat.id, "❌ المستخدم ليس أدمن.")
                else:
                    remove_admin_db(target_id)
                    bot.send_message(
                        message.chat.id,
                        f"✅ تم إزالة صلاحيات الأدمن من المستخدم:\n\n"
                        f"🆔 المعرف: {target_id}\n"
                        f"📛 اليوزر: @{target_data['username']}"
                    )
                    add_activity_log(user_id, "remove_admin", f"Removed admin: {target_id}")
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ معرف المستخدم غير صالح.")
    
    user_states[message.chat.id] = None

@bot.message_handler(commands=['ban'])
def admin_ban_user(message):
    """حظر مستخدم"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, "استخدام: /ban <user_id> [reason]")
        return
    
    try:
        target_id = int(parts[1])
        reason = ' '.join(parts[2:]) if len(parts) > 2 else "Admin ban"
        
        ban_user_db(target_id, reason)
        
        # إيقاف جميع بوتات المستخدم
        bots = get_all_hosted_bots_db(target_id)
        if bots:
            for b in bots:
                terminate_process(b[0])
        
        bot.send_message(message.chat.id, f"✅ تم حظر المستخدم {target_id}")
        add_security_log(message.from_user.id, "admin_ban", f"Banned: {target_id}, Reason: {reason}")
    except ValueError:
        bot.send_message(message.chat.id, "❌ معرف المستخدم غير صالح.")

@bot.message_handler(commands=['unban'])
def admin_unban_user(message):
    """فك حظر مستخدم"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, "استخدام: /unban <user_id>")
        return
    
    try:
        target_id = int(parts[1])
        unban_user_db(target_id)
        bot.send_message(message.chat.id, f"✅ تم فك حظر المستخدم {target_id}")
        add_activity_log(message.from_user.id, "admin_unban", f"Unbanned: {target_id}")
    except ValueError:
        bot.send_message(message.chat.id, "❌ معرف المستخدم غير صالح.")

@bot.message_handler(commands=['backups'])
def list_admin_backups(message):
    """عرض النسخ الاحتياطية للأدمن"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        return
    
    backups = db_execute(
        """SELECT backup_id, user_id, filename, reason, uploaded_at 
           FROM admin_backups ORDER BY uploaded_at DESC LIMIT 20""",
        fetch_all=True
    )
    
    if not backups:
        bot.send_message(message.chat.id, "📭 لا توجد نسخ احتياطية.")
        return
    
    msg = "📁 النسخ الاحتياطية (آخر 20):\n\n"
    
    for backup in backups:
        backup_id, user_id, filename, reason, uploaded_at = backup
        msg += f"📎 #{backup_id}\n"
        msg += f"👤 {user_id} | 📁 {filename}\n"
        msg += f"🎯 {reason}\n"
        msg += f"🕒 {uploaded_at}\n\n"
    
    # إضافة أزرار للتحميل
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    for backup in backups[:5]:  # أول 5 فقط
        backup_id = backup[0]
        btn_download = types.InlineKeyboardButton(f"⬇️ #{backup_id}", callback_data=f"admin_backup_{backup_id}")
        markup.add(btn_download)
    
    if len(msg) > 4000:
        msg = msg[:4000] + "..."
    
    bot.send_message(message.chat.id, msg, reply_markup=markup)

@bot.message_handler(commands=['sentfiles'])
def list_sent_files(message):
    """عرض الملفات المرسلة للأدمن"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        return
    
    sent_files = get_sent_files(20)
    
    if not sent_files:
        bot.send_message(message.chat.id, "📭 لا توجد ملفات مرسلة.")
        return
    
    msg = "📤 الملفات المرسلة للأدمن (آخر 20):\n\n"
    
    for file_data in sent_files:
        file_id, user_id, filename, file_size, file_type, sent_at, is_suspicious, suspicion_reason = file_data
        
        suspicious_emoji = "🚨" if is_suspicious == 1 else "✅"
        file_emoji = "🐍" if file_type == 'python' else "📄"
        
        msg += f"{suspicious_emoji} #{file_id}\n"
        msg += f"{file_emoji} {filename}\n"
        msg += f"👤 {user_id} | 📊 {file_size} بايت\n"
        msg += f"🕒 {sent_at}\n"
        if is_suspicious == 1:
            msg += f"⚠️ {suspicion_reason}\n"
        msg += "\n"
    
    bot.send_message(message.chat.id, msg)

@bot.message_handler(commands=['admins'])
def list_admins_command(message):
    """عرض قائمة الأدمن"""
    if not is_admin(message.from_user.id) and not is_user_admin(message.from_user.id):
        return
    
    admins = get_all_admins()
    
    if not admins:
        bot.send_message(message.chat.id, "📭 لا يوجد أدمن.")
    else:
        msg = "👑 قائمة الأدمن:\n\n"
        
        for admin in admins:
            user_id, username, created_at = admin
            is_main = "⭐" if user_id == ADMIN_ID else ""
            msg += f"{is_main} {user_id} (@{username})\n"
            msg += f"   منذ: {created_at}\n\n"
        
        bot.send_message(message.chat.id, msg)

@bot.callback_query_handler(func=lambda c: c.data.startswith('admin_backup_'))
def handle_admin_backup(call):
    """معالجة تحميل النسخ الاحتياطية"""
    if not is_admin(call.from_user.id) and not is_user_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحية.")
        return
    
    try:
        backup_id = int(call.data.replace('admin_backup_', ''))
        
        # جلب معلومات النسخة الاحتياطية
        backup = db_execute(
            """SELECT backup_path, filename, user_id, reason 
               FROM admin_backups WHERE backup_id = ?""",
            (backup_id,), fetch_one=True
        )
        
        if not backup:
            bot.answer_callback_query(call.id, "❌ النسخة غير موجودة.")
            return
        
        backup_path, filename, user_id, reason = backup
        
        if not os.path.exists(backup_path):
            bot.answer_callback_query(call.id, "❌ الملف غير موجود.")
            return
        
        # إرسال الملف
        with open(backup_path, 'rb') as file:
            caption = f"📎 نسخة احتياطية #{backup_id}\n\n"
            caption += f"👤 المستخدم: {user_id}\n"
            caption += f"📁 الملف: {filename}\n"
            caption += f"🎯 السبب: {reason}\n"
            caption += f"🕒 تم النسخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            bot.send_document(call.message.chat.id, file, visible_file_name=filename, caption=caption)
        
        bot.answer_callback_query(call.id, "✅ تم إرسال الملف")
        
    except Exception as e:
        bot.answer_callback_query(call.id, f"❌ خطأ: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🔄 مراقبة الموارد في الخلفية
# ═══════════════════════════════════════════════════════════════════

def resource_monitor_loop():
    """حلقة مراقبة الموارد"""
    while True:
        try:
            time.sleep(MONITOR_INTERVAL_SECONDS)
            
            for filename in list(running_processes.keys()):
                killed, violations = resource_monitor.kill_if_exceeded(filename)
                
                if killed:
                    # التحقق إذا كانت العملية تابعة لأدمن
                    if filename.startswith('admin_'):
                        # لا نحظر الأدمن، فقط نوقف العملية
                        proc_info = resource_monitor.monitored_processes.get(filename)
                        if proc_info:
                            user_id = proc_info['user_id']
                            violation_msg = ', '.join(violations)
                            
                            try:
                                bot.send_message(
                                    user_id,
                                    f"⚠️ تم إيقاف ملف الأدمن {filename.replace('admin_', '')}!\n\n"
                                    f"السبب: تجاوز حدود الموارد\n"
                                    f"التفاصيل: {violation_msg}"
                                )
                            except:
                                pass
                    else:
                        # معالجة المستخدمين العاديين
                        bot_info = db_execute(
                            "SELECT user_id FROM hosted_bots WHERE filename = ?",
                            (filename,), fetch_one=True
                        )
                        
                        if bot_info:
                            user_id = bot_info[0]
                            violation_msg = ', '.join(violations)
                            
                            ban_user_db(user_id, f"Resource abuse: {violation_msg}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
                            add_security_log(user_id, "resource_abuse", f"File: {filename}, Violations: {violation_msg}", severity='CRITICAL')
                            
                            try:
                                bot.send_message(
                                    user_id,
                                    f"⚠️ تم إيقاف بوتك {filename} وحظرك مؤقتاً!\n\n"
                                    f"السبب: تجاوز حدود الموارد\n"
                                    f"التفاصيل: {violation_msg}"
                                )
                            except:
                                pass
                            
                            if ADMIN_ID:
                                try:
                                    bot.send_message(
                                        ADMIN_ID,
                                        f"🚨 تنبيه - تجاوز موارد\n\n"
                                        f"المستخدم: {user_id}\n"
                                        f"الملف: {filename}\n"
                                        f"السبب: {violation_msg}"
                                    )
                                except:
                                    pass
                
                # التحقق من توقف العمليات
                check_result = resource_monitor.check_process(filename)
                if check_result.get('status') == 'stopped':
                    if filename in running_processes:
                        del running_processes[filename]
                    resource_monitor.remove_process(filename)
                    if not filename.startswith('admin_'):
                        update_hosted_bot_status_db(filename, 'stopped', error_log=check_result.get('reason'))
                    
        except Exception as e:
            print(f"Monitor error: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🚀 تشغيل البوت
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("🚀 جاري تهيئة النظام...")
    
    # تهيئة قاعدة البيانات
    init_db()
    print("✅ تم تهيئة قاعدة البيانات")
    
    # إضافة المطور الرئيسي كأدمن
    if ADMIN_ID:
        add_admin_db(ADMIN_ID, "Main Developer")
        print(f"✅ تم إضافة المطور الرئيسي {ADMIN_ID} كأدمن")
    
    # إنشاء مجلدات الأدمن
    admin_dir = os.path.join(BASE_DIR, 'admin_files')
    admin_backup_dir = os.path.join(BASE_DIR, 'admin_backup')
    admin_alerts_dir = os.path.join(BASE_DIR, 'admin_alerts')
    
    os.makedirs(admin_dir, exist_ok=True)
    os.makedirs(admin_backup_dir, exist_ok=True)
    os.makedirs(admin_alerts_dir, exist_ok=True)
    
    print("✅ تم إنشاء مجلدات الأدمن")
    
    # بدء مراقبة الموارد في خيط منفصل
    monitor_thread = threading.Thread(target=resource_monitor_loop, daemon=True)
    monitor_thread.start()
    print("✅ تم بدء مراقبة الموارد")
    
    # استعادة البوتات الشغالة
    running_bots = db_execute(
        "SELECT filename, user_id, process_pid FROM hosted_bots WHERE status = 'running'",
        fetch_all=True
    )
    
    if running_bots:
        print(f"🔄 جاري استعادة {len(running_bots)} بوت...")
        for bot_data in running_bots:
            filename, user_id, old_pid = bot_data
            sandbox = sandbox_manager.get_user_sandbox(user_id)
            file_path = os.path.join(sandbox['bots'], filename)
            
            if os.path.exists(file_path):
                try:
                    bot_stdout = os.path.join(sandbox['logs'], f"{filename}.stdout")
                    bot_stderr = os.path.join(sandbox['logs'], f"{filename}.stderr")
                    
                    with open(bot_stdout, 'a') as stdout_f, open(bot_stderr, 'a') as stderr_f:
                        process = subprocess.Popen(
                            ['python3', file_path],
                            cwd=sandbox['bots'],
                            stdout=stdout_f,
                            stderr=stderr_f,
                            close_fds=True,
                            start_new_session=True
                        )
                        
                        running_processes[filename] = process
                        resource_monitor.add_process(filename, process.pid, user_id)
                        update_hosted_bot_status_db(filename, 'running', process.pid)
                        print(f"   ✅ {filename}")
                except Exception as e:
                    print(f"   ❌ {filename}: {e}")
                    update_hosted_bot_status_db(filename, 'error', error_log=str(e))
            else:
                update_hosted_bot_status_db(filename, 'stopped', error_log="File not found")
    
    print("=" * 50)
    print("🤖 نظام استضافة البوتات الآمن")
    print("=" * 50)
    print(f"• المطور: {ADMIN_ID}")
    print(f"• القناة: {REQUIRED_CHANNEL_ID}")
    print(f"• حد البوتات: {MAX_BOTS_PER_USER}")
    print(f"• حد RAM: {RESOURCE_RAM_LIMIT_MB}MB")
    print(f"• حد CPU: {RESOURCE_CPU_LIMIT_PERCENT}%")
    print(f"• نظام التحويل الإجباري: ✅ فعال")
    print(f"• جميع الملفات ترسل للأدمن: ✅ مفعل")
    print(f"• نظام إدارة الأدمن: ✅ فعال")
    print("=" * 50)
    print("✅ البوت جاهز للعمل!")
    
    # تشغيل البوت مع معالجة خطأ 409
    import requests as req
    
    # إلغاء webhook قديم إن وجد
    try:
        req.get(f"https://api.telegram.org/bot{API_TOKEN}/deleteWebhook?drop_pending_updates=true", timeout=10)
        time.sleep(2)
    except:
        pass
    
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=60, skip_pending=True)
        except Exception as e:
            error_str = str(e)
            if "409" in error_str or "Conflict" in error_str:
                print("⚠️ خطأ 409: جاري إعادة المحاولة...")
                time.sleep(3)
            else:
                print(f"❌ خطأ: {e}")
                time.sleep(5)