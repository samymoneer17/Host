# =================================================================
# نظام استضافة بوتات تيليجرام الآمن والمحسن (بدون venv)
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
MAX_WORKERS = 100

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
# 🛡️ الطبقة 2: نظام الحماية المتقدم (مبسط)
# ═══════════════════════════════════════════════════════════════════

class AdvancedProtectionSystem:
    """نظام حماية متقدم مع مستويات متعددة (مبسط)"""
    
    def __init__(self, suspicious_dir: str):
        self.suspicious_dir = suspicious_dir
        os.makedirs(suspicious_dir, exist_ok=True)
        
        # الأنماط الخطيرة الحقيقية فقط (بدون كلمة token)
        self.dangerous_patterns = [
            # أوامر حذف وتدمير
            (r'rm\s+-rf\s+[\'"]?/', 'أمر حذف خطير'),
            (r'dd\s+if=.*\s+of=.*', 'أمر نسخ خطير'),
            (r':\(\)\{\s*:\|\:\s*\&\s*\};:', 'قنبلة فورك'),
            
            # أوامر نظام خطيرة
            (r'shutdown\s+-h\s+now', 'إيقاف النظام'),
            (r'reboot\s+-f', 'إعادة تشغيل النظام'),
            (r'halt\s+-f', 'إيقاف النظام'),
            (r'poweroff\s+-f', 'إطفاء النظام'),
            
            # أوامر قتل العمليات
            (r'killall\s+-9', 'قتل جميع العمليات'),
            (r'pkill\s+-9', 'قتل عمليات'),
            
            # أوامر تغيير الصلاحيات
            (r'chmod\s+-R\s+777\s+[\'"]?/', 'تغيير صلاحيات جميع الملفات'),
            (r'chown\s+-R\s+.*\s+/', 'تغيير ملكية الملفات'),
            
            # أوامر إدارة المستخدمين
            (r'useradd\s+.*', 'إضافة مستخدم'),
            (r'userdel\s+.*', 'حذف مستخدم'),
            (r'passwd\s+.*', 'تغيير كلمة المرور'),
            
            # أوامر تنزيل وتنفيذ
            (r'wget\s+.*(http|ftp)', 'تنزيل ملفات من الإنترنت'),
            (r'curl\s+.*(http|ftp)', 'تنزيل ملفات من الإنترنت'),
            (r'python\s+-c\s+.*', 'تنفيذ كود بايثون مباشر'),
            
            # أوامر تشفير وتنفيذ ديناميكي
            (r'__import__\s*\(\s*[\'"]os[\'"]\s*\)', 'استيراد ديناميكي'),
            (r'eval\s*\(', 'تنفيذ كود ديناميكي'),
            (r'exec\s*\(', 'تنفيذ كود ديناميكي'),
            
            # أوامر نظام الملفات الخطيرة
            (r'open\s*\(\s*[\'"]/etc/passwd[\'"]', 'فتح ملفات نظامية'),
            (r'open\s*\(\s*[\'"]/etc/shadow[\'"]', 'فتح ملفات نظامية'),
            (r'open\s*\(\s*[\'"]/root/[\'"]', 'فتح مجلد root'),
            
            # مكتبات خطيرة
            (r'import\s+subprocess', 'استيراد مكتبة العمليات الفرعية'),
            (r'import\s+socket', 'استيراد مكتبة الشبكة'),
            (r'import\s+shutil', 'استيراد مكتبة عمليات الملفات'),
        ]
        
        # الأنماط المسموح بها (مثل كلمة token في التوكن)
        self.allowed_patterns = [
            r'TOKEN\s*=',
            r'BOT_TOKEN\s*=',
            r'API_TOKEN\s*=',
            r'token\s*=',
            r'["\'].*:.*["\']',  # نمط التوكن العادي
        ]
    
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
            
            # أولاً: التحقق من الأنماط المسموح بها
            is_allowed = False
            for pattern in self.allowed_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    is_allowed = True
                    break
            
            # ثم: فحص الأنماط الخطيرة
            for pattern, description in self.dangerous_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # إذا كان النمط المسموح موجود، تخطي
                    if is_allowed and 'token' in pattern.lower():
                        continue
                    
                    suspicious_code = content[max(0, match.start() - 20):min(len(content), match.end() + 20)]
                    activity = f"تم اكتشاف أمر خطير: {match.group(0)} في السياق: {suspicious_code}"
                    
                    # تحديد نوع التهديد
                    if "import" in pattern or "eval" in pattern or "exec" in pattern:
                        threat_type = "malicious_code"
                    else:
                        threat_type = "dangerous_command"
                    
                    # نسخ الملف المشبوه
                    file_name = os.path.basename(file_path)
                    suspicious_file_path = os.path.join(self.suspicious_dir, f"{user_id}_{file_name}")
                    shutil.copy2(file_path, suspicious_file_path)
                    
                    return True, activity, threat_type
            
            return False, None, ""
        except Exception as e:
            logging.error(f"فشل في فحص الملف {file_path}: {e}")
            return False, f"خطأ في الفحص: {e}", "error"
    
    def is_safe_file(self, file_path: str) -> str:
        """التحقق من أن الملف لا يحتوي على تعليمات خطيرة"""
        try:
            with open(file_path, 'rb') as f:
                raw_content = f.read()
                encoding_info = chardet.detect(raw_content)
                encoding = encoding_info['encoding'] or 'utf-8'
                
                content = raw_content.decode(encoding)
                
                # فحص الأنماط الخطيرة
                for pattern, description in self.dangerous_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return f"❌ الملف يحتوي على أوامر خطيرة: {description}"
                
                # تحقق من أن المحتوى نصي
                if not self.is_text(content):
                    return "❌ الملف غير نصي أو مشفر"
                
                return "✅ الملف آمن"
        except Exception as e:
            logging.error(f"Error checking file safety: {e}")
            return f"❌ خطأ في فحص الملف: {e}"
    
    def is_text(self, content: str) -> bool:
        """التحقق مما إذا كان المحتوى نصيًا"""
        # نسبة الأحرف القابلة للطباعة
        printable_count = sum(1 for char in content if char in string.printable)
        return (printable_count / len(content)) > 0.8 if content else False

protection_system = AdvancedProtectionSystem(SUSPICIOUS_FILES_DIR)

# ═══════════════════════════════════════════════════════════════════
# 🔍 محلل الأكواد الأمني (مبسط)
# ═══════════════════════════════════════════════════════════════════

class CodeAnalyzer:
    """محلل الأكواد للكشف عن الأوامر الخطيرة (مبسط)"""
    
    def __init__(self):
        self.forbidden_patterns = [
            # أوامر خطيرة جداً
            (r'os\.system\s*\(.*rm.*', 'أمر حذف خطير'),
            (r'os\.system\s*\(.*shutdown.*', 'إيقاف النظام'),
            (r'os\.system\s*\(.*reboot.*', 'إعادة تشغيل'),
            (r'subprocess\.run\(.*rm.*', 'أمر حذف عبر subprocess'),
            
            # فتح ملفات نظامية
            (r'open\([\'"]/etc/', 'فتح ملفات نظامية'),
            (r'open\([\'"]/root/', 'فتح مجلد root'),
            (r'open\([\'"]/home/', 'فتح مجلدات home'),
            
            # أوامر تنفيذ خطيرة
            (r'__import__\([\'"]os[\'"]\)', 'استيراد ديناميكي'),
            (r'eval\(.*open\(', 'تنفيذ ديناميكي مع فتح ملفات'),
            (r'exec\(.*open\(', 'تنفيذ ديناميكي مع فتح ملفات'),
            
            # مكتبات خطيرة
            (r'import\s+pty', 'مكتبة طرفية خطيرة'),
            (r'import\s+fcntl', 'مكتبة تحكم منخفضة'),
            (r'import\s+resource', 'مكتبة موارد النظام'),
        ]
        
        self.warning_patterns = [
            # أنماط تحذيرية
            (r'import\s+subprocess', 'استيراد مكتبة العمليات الفرعية'),
            (r'import\s+socket', 'استيراد مكتبة الشبكة'),
            (r'import\s+shutil', 'استيراد مكتبة عمليات الملفات'),
        ]
    
    def analyze(self, code: str) -> dict:
        """تحليل شامل للكود"""
        issues = []
        warnings = []
        
        # البحث عن الأنماط المحظورة
        for pattern, description in self.forbidden_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                issues.append({
                    'type': 'forbidden',
                    'description': description,
                    'pattern': pattern
                })
        
        # البحث عن الأنماط التحذيرية
        for pattern, description in self.warning_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                warnings.append({
                    'type': 'warning',
                    'description': description,
                    'pattern': pattern
                })
        
        # حساب درجة الأمان
        security_score = 100
        if issues:
            security_score -= len(issues) * 30
        if warnings:
            security_score -= len(warnings) * 10
        security_score = max(0, security_score)
        
        return {
            'is_safe': len(issues) == 0,
            'security_score': security_score,
            'issues': issues,
            'warnings': warnings,
            'issues_count': len(issues),
            'warnings_count': len(warnings)
        }
    
    def is_malicious(self, code: str) -> tuple:
        """فحص سريع للكود الخبيث"""
        result = self.analyze(code)
        if not result['is_safe']:
            if result['issues']:
                return True, result['issues'][0]['description']
            elif result['warnings']:
                return False, f"تحذير: {result['warnings'][0]['description']}"
        return False, None

code_analyzer = CodeAnalyzer()

# ═══════════════════════════════════════════════════════════════════
# 📦 نظام العزل (Sandbox) بدون venv
# ═══════════════════════════════════════════════════════════════════

class SandboxManager:
    """مدير بيئات العزل للمستخدمين (بدون venv)"""
    
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    
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
    
    def run_script_async(self, script_path: str, chat_id: int, script_name: str):
        """تشغيل الملف البرمجي بشكل غير متزامن"""
        future = self.executor.submit(self._run_script, script_path, chat_id, script_name)
        return future
    
    def _run_script(self, script_path: str, chat_id: int, script_name: str):
        """دالة مساعدة لتشغيل السكربت"""
        try:
            user_id = chat_id
            sandbox = self.get_user_sandbox(user_id)
            
            bot_stdout = os.path.join(sandbox['logs'], f"{script_name}.stdout")
            bot_stderr = os.path.join(sandbox['logs'], f"{script_name}.stderr")
            
            with open(bot_stdout, 'w') as stdout_f, open(bot_stderr, 'w') as stderr_f:
                process = subprocess.Popen(
                    [sys.executable, script_path],
                    cwd=sandbox['bots'],
                    stdout=stdout_f,
                    stderr=stderr_f,
                    close_fds=True,
                    start_new_session=True,
                    env={
                        **os.environ,
                        'PYTHONPATH': sandbox['bots'],
                    }
                )
                
                return process
                
        except Exception as e:
            logging.error(f"Error running script {script_path}: {e}")
            return None

sandbox_manager = SandboxManager(USERS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 📊 نظام مراقبة الموارد
# ═══════════════════════════════════════════════════════════════════

class ResourceMonitor:
    """مراقب موارد البوتات في الوقت الحقيقي"""
    
    LIMITS = {
        'cpu_percent': RESOURCE_CPU_LIMIT_PERCENT,
        'ram_mb': RESOURCE_RAM_LIMIT_MB,
        'processes': MAX_PROCESSES_PER_USER,
    }
    
    def __init__(self):
        self.monitored_processes = {}
        self.user_processes = defaultdict(list)
        self.is_running = False
        self.lock = threading.Lock()
    
    def add_process(self, filename: str, pid: int, user_id: int, chat_id: int):
        """إضافة عملية للمراقبة"""
        with self.lock:
            self.monitored_processes[filename] = {
                'pid': pid,
                'user_id': user_id,
                'chat_id': chat_id,
                'started_at': datetime.now(),
                'violations': 0,
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
            
            # التحقق من التجاوزات
            violations = []
            
            if cpu_percent > self.LIMITS['cpu_percent']:
                violations.append(f"CPU: {cpu_percent:.1f}% > {self.LIMITS['cpu_percent']}%")
            
            if ram_mb > self.LIMITS['ram_mb']:
                violations.append(f"RAM: {ram_mb:.1f}MB > {self.LIMITS['ram_mb']}MB")
            
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
            'total_users': len(self.user_processes),
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
# 📝 نظام التسجيل والمراقبة
# ═══════════════════════════════════════════════════════════════════

class ActivityLogger:
    """نظام تسجيل النشاطات"""
    
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
    
    def log(self, level: str, user_id: int, action: str, details: str = ""):
        """تسجيل نشاط"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] User: {user_id} - {action} - {details}\n"
        
        # حفظ في ملف يومي
        log_file = os.path.join(self.log_dir, f"log_{datetime.now().strftime('%Y-%m-%d')}.txt")
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write log: {e}")
    
    def activity(self, user_id: int, action: str, details: str = ""):
        """تسجيل نشاط عادي"""
        self.log('INFO', user_id, action, details)
    
    def security_alert(self, user_id: int, alert_type: str, details: str, file_name: str = None):
        """تنبيه أمني"""
        alert_msg = f"⚠️ تنبيه أمني: {alert_type}\nالمستخدم: {user_id}\nالتفاصيل: {details}"
        if file_name:
            alert_msg += f"\nالملف: {file_name}"
        
        # تسجيل في السجلات
        self.log('SECURITY', user_id, alert_type, f"{details} | File: {file_name}")
        
        # إرسال للأدمن
        for admin_id in ADMIN_IDS:
            try:
                bot.send_message(admin_id, alert_msg)
            except Exception as e:
                print(f"Failed to send alert to admin {admin_id}: {e}")
    
    def error(self, user_id: int, action: str, error: str):
        """تسجيل خطأ"""
        self.log('ERROR', user_id, action, error)

activity_logger = ActivityLogger(LOGS_DIR)

# ═══════════════════════════════════════════════════════════════════
# 🗄️ قاعدة البيانات المبسطة
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
            first_name TEXT,
            last_name TEXT,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            ban_timestamp TEXT,
            total_uploads INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP
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
            start_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
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
# 🔧 وظائف المساعدة
# ═══════════════════════════════════════════════════════════════════

# قواميس التتبع
user_states = {}
running_processes = {}
user_files = defaultdict(list)
banned_users = set()
bot_scripts = defaultdict(lambda: {'processes': [], 'name': '', 'path': '', 'uploader': ''})

def is_admin(user_id):
    """التحقق من صلاحيات المطور"""
    return user_id in ADMIN_IDS

def get_user_limits(user_id):
    """جلب حدود المستخدم"""
    if is_admin(user_id):
        # الأدمن بدون حدود
        return {
            'max_bots': 100,
            'max_file_size_mb': 100,
            'cpu_limit_percent': 100,
            'ram_limit_mb': 4096,
            'disk_limit_mb': 10240,
        }
    else:
        # المستخدم العادي
        return {
            'max_bots': MAX_BOTS_PER_USER,
            'max_file_size_mb': MAX_FILE_SIZE_MB,
            'cpu_limit_percent': RESOURCE_CPU_LIMIT_PERCENT,
            'ram_limit_mb': RESOURCE_RAM_LIMIT_MB,
            'disk_limit_mb': RESOURCE_DISK_LIMIT_MB,
        }

def get_user_data(user_id):
    """جلب بيانات المستخدم"""
    result = db_execute(
        "SELECT user_id, username, first_name, last_name, is_banned, ban_reason FROM users WHERE user_id = ?",
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

def ban_user_db(user_id, reason="Generic ban", is_temp=False, duration_minutes=None):
    """حظر مستخدم"""
    if is_temp and duration_minutes:
        ban_until = datetime.now() + timedelta(minutes=duration_minutes)
        db_execute(
            """UPDATE users SET is_banned = 1, ban_reason = ?, 
               ban_timestamp = ? WHERE user_id = ?""",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )
    else:
        db_execute(
            """UPDATE users SET is_banned = 1, ban_reason = ?, 
               ban_timestamp = ? WHERE user_id = ?""",
            (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id),
            commit=True
        )
    
    banned_users.add(user_id)
    activity_logger.security_alert(user_id, "user_banned", f"User banned for: {reason}")

def unban_user_db(user_id):
    """فك حظر مستخدم"""
    result = db_execute(
        "UPDATE users SET is_banned = 0, ban_reason = NULL, ban_timestamp = NULL WHERE user_id = ?",
        (user_id,), commit=True
    )
    
    if user_id in banned_users:
        banned_users.remove(user_id)
    
    return result

def add_hosted_bot_db(user_id, filename, pid=None, status='running', bot_username=None, 
                      bot_name=None, encrypted_token=None):
    """إضافة بوت مستضاف"""
    db_execute(
        """INSERT OR REPLACE INTO hosted_bots 
           (user_id, filename, status, process_pid, bot_username, bot_name, 
            bot_token_encrypted, last_started, start_count) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT start_count FROM hosted_bots WHERE filename = ?), 0) + 1)""",
        (user_id, filename, status, pid, bot_username, bot_name, encrypted_token,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), filename),
        commit=True
    )

def update_hosted_bot_status_db(filename, status, pid=None):
    """تحديث حالة البوت"""
    if pid:
        db_execute(
            "UPDATE hosted_bots SET status = ?, process_pid = ? WHERE filename = ?",
            (status, pid, filename), commit=True
        )
    else:
        db_execute(
            "UPDATE hosted_bots SET status = ?, process_pid = NULL, last_started = NULL WHERE filename = ?",
            (status, filename), commit=True
        )

def delete_hosted_bot_db(filename):
    """حذف بوت من قاعدة البيانات"""
    db_execute("DELETE FROM hosted_bots WHERE filename = ?", (filename,), commit=True)

def get_all_hosted_bots_db(user_id=None):
    """جلب جميع البوتات المستضافة"""
    if user_id:
        return db_execute(
            """SELECT filename, status, user_id, process_pid, last_started, 
               start_count, bot_username, bot_name 
               FROM hosted_bots WHERE user_id = ?""",
            (user_id,), fetch_all=True
        )
    return db_execute(
        """SELECT filename, status, user_id, process_pid, last_started, 
           start_count, bot_username, bot_name 
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

def save_chat_id(chat_id):
    """حفظ chat_id للمستخدمين الذين يتفاعلون مع البوت"""
    if chat_id not in user_files:
        user_files[chat_id] = []
        print(f"تم حفظ chat_id: {chat_id}")
    else:
        print(f"chat_id: {chat_id} موجود بالفعل")

# ═══════════════════════════════════════════════════════════════════
# 🔄 دوال إدارة العمليات
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

# ═══════════════════════════════════════════════════════════════════
# 📤 معالجة رفع الملفات
# ═══════════════════════════════════════════════════════════════════

def process_python_file(message, file_content, filename, user_id):
    """معالجة ملف بايثون"""
    bot.send_message(message.chat.id, "⏳ جاري فحص الملف وتحليله...")
    
    # حفظ مؤقت للفحص
    temp_path = os.path.join(tempfile.gettempdir(), filename)
    with open(temp_path, 'wb') as temp_file:
        temp_file.write(file_content)
    
    # فحص الحماية الأساسي (استثناء الأدمن)
    if user_id not in ADMIN_IDS:
        is_malicious, activity, threat_type = protection_system.scan_file(temp_path, user_id)
        
        if is_malicious:
            bot.reply_to(message, f"⛔ تم رفض ملفك: {activity}")
            ban_user_db(user_id, f"Malicious code: {activity}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
            os.remove(temp_path)
            return
    
    # فحص الكود
    try:
        code = file_content.decode('utf-8', errors='ignore')
    except:
        bot.send_message(message.chat.id, "❌ لا يمكن قراءة الملف. يرجى استخدام ترميز UTF-8.")
        os.remove(temp_path)
        return
    
    # الخطوة 1: كشف التوكنات
    detected_tokens = token_protector.detect_tokens(code)
    
    if not detected_tokens:
        bot.send_message(
            message.chat.id,
            "❌ لم يتم العثور على توكن بوت تيليجرام في الملف!\n\n"
            "يجب أن يحتوي الملف على توكن بوت صالح."
        )
        os.remove(temp_path)
        return
    
    # الخطوة 2: التحقق من صلاحية التوكن
    token = detected_tokens[0]
    token_info = token_protector.validate_telegram_token(token)
    
    if not token_info['valid']:
        bot.send_message(
            message.chat.id,
            f"❌ التوكن الموجود في الملف غير صالح!\n\n"
            f"خطأ: {token_info.get('error', 'غير معروف')}"
        )
        os.remove(temp_path)
        return
    
    if not token_info.get('is_bot'):
        bot.send_message(
            message.chat.id,
            "❌ التوكن المقدم ليس لبوت تيليجرام!\n"
            "يرجى استخدام توكن بوت صالح من @BotFather"
        )
        os.remove(temp_path)
        return
    
    bot_username = token_info.get('bot_username', 'Unknown')
    bot_name = token_info.get('bot_name', 'Unknown')
    
    # الخطوة 3: فحص الكود للأوامر الخطيرة
    is_malicious_code, malicious_reason = code_analyzer.is_malicious(code)
    
    if is_malicious_code:
        ban_user_db(user_id, f"Malicious code: {malicious_reason}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
        
        bot.send_message(
            message.chat.id,
            f"🚫 تم اكتشاف كود خطير في ملفك!\n\n"
            f"السبب: {malicious_reason}\n\n"
            f"تم حظرك مؤقتاً لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة.\n"
            "يرجى التواصل مع المطور إذا كنت تعتقد أن هذا خطأ."
        )
        
        os.remove(temp_path)
        return
    
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
    if not is_admin(user_id):
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
    
    # الخطوة 6: تشغيل البوت
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
                    f"🔒 التوكن: محمي ومشفر\n\n"
                    f"البوت يعمل الآن بشكل دائم!"
                )
                activity_logger.activity(user_id, "bot_started", f"File: {filename}, Bot: @{bot_username}")
            else:
                bot.send_message(
                    message.chat.id,
                    "❌ حدث خطأ أثناء تشغيل البوت.\n"
                    "قد يكون هناك خطأ في الكود أو المكتبات."
                )
                update_hosted_bot_status_db(filename, 'error')
                
                if filename in running_processes:
                    del running_processes[filename]
                resource_monitor.remove_process(filename)
        
        os.remove(temp_path)
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ غير متوقع: {e}")
        os.remove(temp_path)

def process_admin_file(message, file_content, filename, admin_id):
    """معالجة ملفات الأدمن"""
    try:
        sandbox = sandbox_manager.get_user_sandbox(admin_id)
        file_path = os.path.join(sandbox['bots'], filename)
        
        with open(file_path, 'wb') as f:
            f.write(file_content)
        
        # تشغيل الملف إذا كان .py
        if filename.endswith('.py'):
            bot.send_message(message.chat.id, "⏳ جاري تشغيل الملف...")
            
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
                    f"📁 المسار: {file_path}"
                )
                activity_logger.activity(admin_id, "admin_file_run", f"File: {filename}")
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
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
        return
    
    # التحقق من الاشتراك
    if REQUIRED_CHANNEL_ID:
        try:
            member_status = bot.get_chat_member(REQUIRED_CHANNEL_ID, user_id).status
            if member_status not in ['member', 'administrator', 'creator']:
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
        except:
            pass
    
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn_upload = types.KeyboardButton('📤 رفع بوت')
    btn_my_bots = types.KeyboardButton('🤖 بوتاتي')
    btn_stats = types.KeyboardButton('📊 إحصائياتي')
    btn_help = types.KeyboardButton('❓ المساعدة')
    
    # إضافة زر خاص للأدمن فقط
    if is_admin(user_id):
        btn_admin_upload = types.KeyboardButton('👑 رفع ملف (أدمن)')
        markup.add(btn_upload, btn_my_bots, btn_stats, btn_help, btn_admin_upload)
    else:
        markup.add(btn_upload, btn_my_bots, btn_stats, btn_help)
    
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
• حجم الملف: {limits['max_file_size_mb']}MB
• RAM: {limits['ram_limit_mb']}MB
• CPU: {limits['cpu_limit_percent']}%
• التخزين: {limits['disk_limit_mb']}MB

استخدم الأزرار للتنقل."""

    bot.send_message(message.chat.id, welcome_text, reply_markup=markup)
    activity_logger.activity(user_id, "start_command", "")

@bot.message_handler(func=lambda m: m.text == '📤 رفع بوت')
def request_file_upload(message):
    """طلب رفع ملف"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور من استخدام البوت.")
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
        "ملاحظة: سيتم فحص الملف أمنياً قبل التشغيل."
    )
    activity_logger.activity(user_id, "request_upload", "")

@bot.message_handler(func=lambda m: m.text == '👑 رفع ملف (أدمن)')
def request_admin_upload(message):
    """طلب رفع ملف من الأدمن"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    if not is_admin(user_id):
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
        f"أرسل الملف الذي تريد رفعه:"
    )
    activity_logger.activity(user_id, "admin_upload_request", "")

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
    
    filename = message.document.file_name
    
    try:
        file_info = bot.get_file(message.document.file_id)
        file_content = bot.download_file(file_info.file_path)
        
        limits = get_user_limits(user_id)
        
        # التحقق من الحجم
        if len(file_content) > MAX_FILE_SIZE_BYTES:
            bot.send_message(
                message.chat.id,
                f"⛔ حجم الملف كبير جداً للفحص الفوري ({MAX_FILE_SIZE_BYTES//1024//1024}MB)!\n"
                f"الرجاء استخدام ملف أصغر."
            )
            return
        
        # حالة رفع ملف أدمن
        if user_states.get(message.chat.id) == 'awaiting_admin_file' and is_admin(user_id):
            user_states[message.chat.id] = None
            bot.send_message(message.chat.id, "👑 جاري رفع الملف بدون فحص...")
            process_admin_file(message, file_content, filename, user_id)
            return
        
        # إذا كان ملف بوت (.py) وكان في حالة انتظار ملف بوت
        elif filename.endswith('.py') and user_states.get(message.chat.id) == 'awaiting_bot_file':
            user_states[message.chat.id] = None
            process_python_file(message, file_content, filename, user_id)
        
        else:
            bot.reply_to(
                message,
                f"❌ هذا النوع من الملفات غير مدعوم.\n"
                f"يرجى إرسال ملف بايثون (.py) فقط."
            )
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ في معالجة الملف: {e}")

@bot.message_handler(func=lambda m: m.text == '🤖 بوتاتي')
def list_my_bots(message):
    """عرض بوتات المستخدم"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, "⛔ أنت محظور.")
        return
    
    bots = get_all_hosted_bots_db(user_id)
    
    if not bots:
        bot.send_message(message.chat.id, "📭 ليس لديك أي بوتات مستضافة.")
        return
    
    msg = "🤖 بوتاتك المستاحة:\n\n"
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    for bot_data in bots:
        filename, status, _, pid, last_started, start_count, bot_username, bot_name = bot_data
        
        status_emoji = "🟢" if status == 'running' else "🔴" if status == 'error' else "⚪"
        
        msg += f"{status_emoji} {filename}\n"
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
    activity_logger.activity(user_id, "view_bots", "")

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
            activity_logger.activity(user_id, "stop_bot", filename)
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
                activity_logger.activity(user_id, "start_bot", filename)
            else:
                bot.send_message(call.message.chat.id, f"❌ فشل التشغيل: {message}")
        else:
            bot.send_message(call.message.chat.id, "❌ ملف البوت غير موجود!")
    
    elif action == 'delete':
        if terminate_process(filename, delete=True):
            bot.send_message(call.message.chat.id, f"✅ تم حذف البوت: {filename}")
            activity_logger.activity(user_id, "delete_bot", filename)
        else:
            bot.send_message(call.message.chat.id, f"⚠️ فشل الحذف أو الملف غير موجود.")
    
    bot.answer_callback_query(call.id)

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
    
    limits = get_user_limits(user_id)
    
    msg = f"""📊 إحصائياتك:

👤 المستخدم: {user_data['username']}
🆔 المعرف: {user_id}
👑 الصلاحية: {'أدمن 👑' if is_admin(user_id) else 'مستخدم عادي'}

🤖 البوتات:
• المجموع: {len(bots) if bots else 0}/{limits['max_bots']}
• قيد التشغيل: {running_count}

💾 التخزين:
• المستخدم: {disk_usage:.2f}MB
• الحد: {limits['disk_limit_mb']}MB

🔒 الحالة:
• الحالة: {'محظور ⛔' if user_data['is_banned'] else 'نشط ✅'}
"""
    
    bot.send_message(message.chat.id, msg)

@bot.message_handler(func=lambda m: m.text == '❓ المساعدة')
def show_help(message):
    """عرض المساعدة"""
    user_id = message.from_user.id
    update_user_seen(user_id)
    
    limits = get_user_limits(user_id)
    
    help_text = f"""❓ دليل الاستخدام:

📤 رفع بوت:
• أرسل ملف .py يحتوي على توكن بوت تيليجرام
• النظام يتأكد من صحة التوكن تلقائياً
• كل ملف يفحص بواسطة نظام حماية

📊 إحصائياتي:
• عرض معلومات حسابك
• عدد البوتات واستخدام التخزين

🤖 بوتاتي:
• عرض جميع بوتاتك
• التحكم في البوتات (تشغيل/إيقاف/حذف)
"""
    
    if is_admin(user_id):
        help_text += f"""
👑 ميزات الأدمن:
• رفع أي ملف بدون فحص أمني
• تشغيل ملفات بايثون مباشرة
"""
    
    help_text += f"""
⚙️ حدود حسابك:
• عدد البوتات: {limits['max_bots']}
• حجم الملف: {limits['max_file_size_mb']}MB
• RAM: {limits['ram_limit_mb']}MB
• CPU: {limits['cpu_limit_percent']}%
• التخزين: {limits['disk_limit_mb']}MB

⚠️ انتهاك القواعد يؤدي للحظر الفوري!
"""
    
    bot.send_message(message.chat.id, help_text)

# ═══════════════════════════════════════════════════════════════════
# 🛠️ أوامر المطور والإدارة
# ═══════════════════════════════════════════════════════════════════

@bot.message_handler(commands=['admin'])
def admin_panel(message):
    """لوحة تحكم المطور"""
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    update_user_seen(message.from_user.id)
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    
    buttons = [
        ('📊 الإحصائيات', 'admin_stats'),
        ('🤖 البوتات', 'admin_bots'),
        ('👥 المستخدمين', 'admin_users'),
        ('🚫 المحظورين', 'admin_banned'),
        ('🔄 إعادة تشغيل الكل', 'admin_reboot_all'),
    ]
    
    for text, callback in buttons:
        markup.add(types.InlineKeyboardButton(text, callback_data=callback))
    
    bot.send_message(
        message.chat.id,
        "🛠️ لوحة تحكم المطور\n\nاختر الإجراء المطلوب:",
        reply_markup=markup
    )
    activity_logger.activity(message.from_user.id, "admin_panel", "")

@bot.callback_query_handler(func=lambda c: c.data.startswith('admin_'))
def handle_admin_panel_actions(call):
    """معالجة أوامر لوحة الأدمن"""
    if not is_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "⛔ ليس لديك صلاحيات.")
        return
    
    update_user_seen(call.from_user.id)
    action = call.data.replace('admin_', '')
    
    if action == 'stats':
        total_users = db_execute("SELECT COUNT(*) FROM users", fetch_one=True)[0] or 0
        banned_users_count = db_execute("SELECT COUNT(*) FROM users WHERE is_banned = 1", fetch_one=True)[0] or 0
        total_bots = db_execute("SELECT COUNT(*) FROM hosted_bots", fetch_one=True)[0] or 0
        running_bots = db_execute("SELECT COUNT(*) FROM hosted_bots WHERE status = 'running'", fetch_one=True)[0] or 0
        
        system_stats = resource_monitor.get_system_stats()
        
        msg = f"""📊 إحصائيات النظام:

👥 المستخدمين:
• المجموع: {total_users}
• المحظورين: {banned_users_count}

🤖 البوتات:
• المجموع: {total_bots}
• قيد التشغيل: {running_bots}
• متوقفة: {total_bots - running_bots}

💻 موارد النظام:
• CPU: {system_stats.get('cpu_percent', 0):.1f}%
• RAM: {system_stats.get('ram_used_mb', 0):.0f}/{system_stats.get('ram_total_mb', 0):.0f}MB ({system_stats.get('ram_percent', 0):.1f}%)
• Disk: {system_stats.get('disk_percent', 0):.1f}%
• عمليات نشطة: {system_stats.get('active_processes', 0)}
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
        activity_logger.activity(call.from_user.id, "admin_reboot_all", f"Rebooted: {rebooted}")
    
    bot.answer_callback_query(call.id)

@bot.message_handler(commands=['ban'])
def ban_user_command(message):
    """حظر مستخدم (للأدمن فقط)"""
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم: /ban <user_id> [reason]")
            return
        
        target_user_id = int(parts[1])
        reason = " ".join(parts[2:]) if len(parts) > 2 else "حظر من الأدمن"
        
        # حظر المستخدم
        ban_user_db(target_user_id, reason, is_temp=False)
        
        # إيقاف جميع بوتات المستخدم
        bots = get_all_hosted_bots_db(target_user_id)
        for bot_data in bots:
            filename = bot_data[0]
            terminate_process(filename)
        
        bot.send_message(
            message.chat.id,
            f"✅ تم حظر المستخدم {target_user_id} بشكل دائم.\n"
            f"السبب: {reason}\n"
            f"تم إيقاف {len(bots)} بوت."
        )
        
    except ValueError:
        bot.send_message(message.chat.id, "❌ user_id يجب أن يكون رقماً.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ خطأ: {e}")

@bot.message_handler(commands=['unban'])
def unban_user_command(message):
    """فك حظر مستخدم (للأدمن فقط)"""
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "⛔ ليس لديك صلاحيات.")
        return
    
    try:
        parts = message.text.split()
        if len(parts) < 2:
            bot.send_message(message.chat.id, "⚠️ استخدم: /unban <user_id>")
            return
        
        target_user_id = int(parts[1])
        
        # فك الحظر
        if unban_user_db(target_user_id):
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
    if not is_admin(message.from_user.id):
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
                        update_hosted_bot_status_db(filename, 'error')
                except Exception as e:
                    logging.error(f"   ❌ {filename}: {e}")
                    update_hosted_bot_status_db(filename, 'error')
            else:
                update_hosted_bot_status_db(filename, 'stopped')

def cleanup_old_files():
    """تنظيف الملفات القديمة"""
    try:
        # تنظيف الملفات المؤقتة القديمة
        for user_dir in os.listdir(USERS_DIR):
            if user_dir.startswith('user_'):
                user_id = user_dir.replace('user_', '')
                if user_id.isdigit():
                    sandbox_manager.cleanup_user_temp(int(user_id))
        
        logging.info("✅ تم تنظيف الملفات القديمة")
    except Exception as e:
        logging.error(f"خطأ في تنظيف الملفات: {e}")

# ═══════════════════════════════════════════════════════════════════
# 🚀 تشغيل البوت الرئيسي
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("🚀 جاري تهيئة النظام...")
    
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
    
    # بدء مراقبة الموارد
    start_monitoring()
    print("✅ تم بدء مراقبة الموارد")
    
    # استعادة البوتات الشغالة
    restore_running_bots()
    
    # تنظيف الملفات القديمة
    cleanup_old_files()
    
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
                time.sleep(10)