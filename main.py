# المكتبات الأساسية
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
from datetime import datetime, timedelta
from collections import defaultdict

# --- 1. إعدادات البوت ---
API_TOKEN = '8156912979:AAF7lmavpv_5HJlziXpygqshsGvqW4tOcDc'
ADMIN_ID = 7627857345  # أنت كأدمن
REQUIRED_CHANNEL_ID = '@pythonyemen1'

UPLOADED_BOTS_DIR = 'uploaded_bots'
DATABASE_FILE = 'bot_data.db'

# قيود الاستخدام والموارد
MAX_FILE_SIZE_MB = 5
MAX_BOTS_PER_USER = 3
RESOURCE_CPU_LIMIT_PERCENT = 80
RESOURCE_RAM_LIMIT_MB = 200

# معدلات الأمان
SECURITY_FAILURE_THRESHOLD = 5
SECURITY_BAN_DURATION_MINUTES = 30

bot = telebot.TeleBot(API_TOKEN)

# --- دالة تهريب الرموز الخاصة ---
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

# --- 2. تهيئة المجلدات وقاعدة البيانات ---
os.makedirs(UPLOADED_BOTS_DIR, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            ban_timestamp TEXT,
            temp_ban_until TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hosted_bots (
            bot_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT UNIQUE,
            status TEXT DEFAULT 'stopped',
            process_pid INTEGER,
            last_started TEXT,
            last_stopped TEXT,
            start_count INTEGER DEFAULT 0,
            error_log TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            details TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            action TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

# --- 3. قواميس لتتبع الحالات ---
user_states = {}
running_processes = {}
security_failures = defaultdict(lambda: {'count': 0, 'last_failure': None})

# --- 4. وظائف قاعدة البيانات ---
def db_execute(query, params=(), fetch_one=False, fetch_all=False, commit=False):
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

def get_user_data(user_id):
    result = db_execute("SELECT user_id, username, is_banned, ban_reason, temp_ban_until FROM users WHERE user_id = ?", (user_id,), fetch_one=True)
    if result:
        return {
            'user_id': result[0],
            'username': result[1],
            'is_banned': bool(result[2]),
            'ban_reason': result[3],
            'temp_ban_until': datetime.strptime(result[4], '%Y-%m-%d %H:%M:%S') if result[4] else None
        }
    return None

def register_user(user_id, username):
    db_execute("INSERT OR IGNORE INTO users (user_id, username) VALUES (?, ?)", (user_id, username), commit=True)

def ban_user_db(user_id, reason="Generic ban", is_temp=False, duration_minutes=None):
    if is_temp and duration_minutes:
        ban_until = datetime.now() + timedelta(minutes=duration_minutes)
        db_execute("UPDATE users SET is_banned = 1, ban_reason = ?, ban_timestamp = ?, temp_ban_until = ? WHERE user_id = ?",
                   (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ban_until.strftime('%Y-%m-%d %H:%M:%S'), user_id), commit=True)
    else:
        db_execute("UPDATE users SET is_banned = 1, ban_reason = ?, ban_timestamp = ?, temp_ban_until = NULL WHERE user_id = ?",
                   (reason, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id), commit=True)

def unban_user_db(user_id):
    return db_execute("UPDATE users SET is_banned = 0, ban_reason = NULL, ban_timestamp = NULL, temp_ban_until = NULL WHERE user_id = ?", (user_id,), commit=True)

def get_banned_users_db():
    return db_execute("SELECT user_id, username, ban_reason, temp_ban_until FROM users WHERE is_banned = 1", fetch_all=True)

def add_hosted_bot_db(user_id, filename, pid=None, status='running'):
    db_execute("INSERT OR REPLACE INTO hosted_bots (user_id, filename, status, process_pid, last_started, start_count) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT start_count FROM hosted_bots WHERE filename = ?), 0) + 1)",
               (user_id, filename, status, pid, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), filename), commit=True)

def update_hosted_bot_status_db(filename, status, pid=None, error_log=None):
    if pid:
        db_execute("UPDATE hosted_bots SET status = ?, process_pid = ?, error_log = NULL WHERE filename = ?", (status, pid, filename), commit=True)
    else:
        db_execute("UPDATE hosted_bots SET status = ?, process_pid = NULL, last_stopped = ?, error_log = ? WHERE filename = ?",
                   (status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), error_log, filename), commit=True)

def delete_hosted_bot_db(filename):
    db_execute("DELETE FROM hosted_bots WHERE filename = ?", (filename,), commit=True)

def get_all_hosted_bots_db(user_id=None):
    if user_id:
        return db_execute("SELECT filename, status, user_id, process_pid, last_started, start_count FROM hosted_bots WHERE user_id = ?", (user_id,), fetch_all=True)
    return db_execute("SELECT filename, status, user_id, process_pid, last_started, start_count FROM hosted_bots", fetch_all=True)

def get_user_bot_count(user_id):
    result = db_execute("SELECT COUNT(*) FROM hosted_bots WHERE user_id = ? AND status = 'running'", (user_id,), fetch_one=True)
    return result[0] if result else 0

def add_security_log(user_id, action, details):
    db_execute("INSERT INTO security_logs (user_id, action, details) VALUES (?, ?, ?)", (user_id, action, details), commit=True)

def add_activity_log(user_id, action, details):
    db_execute("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)", (user_id, action, details), commit=True)

# --- 5. وظائف المساعدة والأمان ---
def is_admin(user_id):
    return user_id == ADMIN_ID

def is_subscribed(user_id, channel_id_str):
    try:
        member = bot.get_chat_member(channel_id_str, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except telebot.apihelper.ApiTelegramException as e:
        if "Bad Request: user not found" in str(e):
             return False
        elif "Bad Request: chat not found" in str(e) or "Bad Request: CHANNEL_INVALID" in str(e):
            print(f"Error: Channel ID '{channel_id_str}' might be invalid or bot is not in it. Error: {e}")
            if is_admin(user_id):
                bot.send_message(ADMIN_ID, f"⚠️ تنبيه مطور - خطأ في القناة: معرف القناة {channel_id_str} غير صالح أو البوت ليس عضواً فيه")
            return False
        else:
            print(f"An unexpected error occurred while checking subscription for user {user_id}: {e}")
            return False
    except Exception as e:
        print(f"An unexpected error occurred while checking subscription for user {user_id}: {e}")
        return False

def terminate_process(filename):
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
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except psutil.NoSuchProcess:
            print(f"Process for {filename} (PID: {process.pid}) no longer exists. Already stopped.")
            if filename in running_processes:
                del running_processes[filename]
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except Exception as e:
            print(f"Error terminating process for {filename}: {e}")
            return False
    
    bot_info = db_execute("SELECT process_pid, status FROM hosted_bots WHERE filename = ?", (filename,), fetch_one=True)
    if bot_info and bot_info[1] == 'running' and bot_info[0] and psutil.pid_exists(bot_info[0]):
        try:
            p = psutil.Process(bot_info[0])
            p.terminate()
            p.wait(timeout=5)
            if p.is_running():
                p.kill()
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except psutil.NoSuchProcess:
            update_hosted_bot_status_db(filename, 'stopped')
            return True
        except Exception as e:
            print(f"Error terminating process from DB for {filename}: {e}")
            return False
    return False

def analyze_for_malicious_code(file_path):
    malicious_patterns = [
        r'import\s+(os|subprocess|sys|shutil|socket|requests|urllib|webbrowser|json|pickle|base64|marshal|pty|asyncio|threading|ctypes|inspect|code|gc|sqlite3|mysql|psycopg2|paramiko|pwn|pwntools|fabric|setproctitle|resource|dlfcn|asyncio)',
        r'(subprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|os\.(system|popen|exec|fork|kill|remove|unlink|rmdir|makedirs|chown|chmod))',
        r'eval\(|exec\(|__import__\s*\(',
        r'(getattr|setattr|delattr)\(|\b(globals|locals|vars)\s*\(',
        r'compile\(',
        r'open\s*\(".*?(token|password|config|creds|secret|ssh|key|pem|env|wallet|private_key|api_key|database|db_url).*?"',
        r'(requests\.(get|post|put|delete|head|options|patch)|urllib\.request\.(urlopen|Request))\s*\(.*?url\s*=\s*["\']?http[s]?://',
        r'\.(send|recv|connect|bind|listen|accept)\(',
        r'(exit|quit|sys\.exit)\s*\(|raise\s+(SystemExit|KeyboardInterrupt)',
        r'daemon\s*=\s*True',
        r'__file__\s*=\s*.*?__import__',
        r'(bot\.run|client\.run|app\.run)\(',
        r'(flask|django|aiohttp|fastapi|sanic|cherrypy|tornado)\.',
        r'cryptography\.|hashlib\.',
        r'shutil\.rmtree',
        r'json\.load\(.*?open\(',
        r'requests\.sessions\.Session',
        r'platform\.(system|machine|processor|version|node|uname)',
        r'socket\.gethostname|getpass\.getuser',
        r'psutil\.(cpu|memory|disk|net|process|users|boot_time)',
        r'telebot\.send_message\(.*?chat_id=(?!' + str(ADMIN_ID) + r')',
        r'telebot\.apihelper\.proxy',
        r'base64\.b64decode|zlib\.decompress|binascii\.unhexlify',
        r'execv|execle|execlp',
        r'asyncio\.create_task\(.*?send_message',
        r'input\(',
        r'open\s*\(.*?,\s*["\']a["\']\)',
        r're\.compile\(.*?\.?import',
        r'sys\.settrace|sys\.setprofile',
        r'subprocess\.PIPE\s*,\s*subprocess\.STDOUT',
        r'socketserver\.|http\.server\.|wsgiref\.simple_server\.',
        r'secrets\.',
        r'uuid\.',
        r'random\.',
        r'time\.sleep\(.*?\d{2,}\)',
        r'__builtin__|__builtins__',
        r'mmap\.',
        r'tempfile\.',
        r'os\.chmod',
        r'os\.chown',
        r'os\.link|os\.symlink',
    ]

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
        if re.search(r'[\w-]{30,}:[\w-]{30,}', content):
            bot.send_message(ADMIN_ID, f"🔐 تنبيه أمني - توكن بوت: تم رفع ملف {os.path.basename(file_path)} وقد يحتوي على توكن بوت داخله")

        for pattern in malicious_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True, pattern
    return False, None

# --- 6. وظائف مراقبة الموارد ---
async def monitor_bot_resources():
    while True:
        await asyncio.sleep(60)
        bots_to_stop = []
        for filename in list(running_processes.keys()):
            process_obj = running_processes.get(filename)
            if not process_obj: continue
            
            try:
                if process_obj.poll() is not None:
                    print(f"Process for {filename} has stopped unexpectedly. Updating status.")
                    stderr_output = ""
                    update_hosted_bot_status_db(filename, 'error', error_log=f"Process stopped unexpectedly. Output: {stderr_output[:1000]}")
                    bot_data = db_execute("SELECT user_id FROM hosted_bots WHERE filename = ?", (filename,), fetch_one=True)
                    user_id_bot_owner = bot_data[0] if bot_data else "Unknown"
                    if user_id_bot_owner != "Unknown":
                        bot.send_message(user_id_bot_owner, f"عذراً، البوت الخاص بك {filename} توقف بشكل غير متوقع. يرجى التحقق من الكود.")

                    if stderr_output:
                        bot.send_message(ADMIN_ID, f"⚠️ تنبيه مطور - بوت توقف: البوت {filename} توقف بشكل غير متوقع")
                    del running_processes[filename]
                    continue

                process_psutil = psutil.Process(process_obj.pid)
                cpu_percent = process_psutil.cpu_percent(interval=None)
                memory_info = process_psutil.memory_info()
                ram_mb = memory_info.rss / (1024 * 1024)

                if cpu_percent > RESOURCE_CPU_LIMIT_PERCENT:
                    bots_to_stop.append((filename, f"تجاوز حد استخدام CPU: {cpu_percent:.2f}%", process_obj.pid))
                elif ram_mb > RESOURCE_RAM_LIMIT_MB:
                    bots_to_stop.append((filename, f"تجاوز حد استخدام RAM: {ram_mb:.2f}MB", process_obj.pid))

            except psutil.NoSuchProcess:
                print(f"Process for {filename} not found by psutil. Likely already stopped.")
                update_hosted_bot_status_db(filename, 'stopped', error_log="Process not found by monitor")
                if filename in running_processes:
                    del running_processes[filename]
            except Exception as e:
                print(f"Error monitoring {filename}: {e}")
                bot.send_message(ADMIN_ID, f"⚠️ تنبيه مطور - خطأ مراقبة: حدث خطأ أثناء مراقبة البوت {filename}")

        for filename, reason, pid in bots_to_stop:
            bot_data = db_execute("SELECT user_id FROM hosted_bots WHERE filename = ?", (filename,), fetch_one=True)
            user_id = bot_data[0] if bot_data else "Unknown"
            
            try:
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
                    p.terminate()
                    p.wait(timeout=5)
                    if p.is_running():
                        p.kill()
                    if filename in running_processes:
                        del running_processes[filename]
                    update_hosted_bot_status_db(filename, 'stopped', error_log=reason)
            except psutil.NoSuchProcess:
                print(f"Process {pid} for {filename} not found during termination.")
                update_hosted_bot_status_db(filename, 'stopped', error_log=reason)
            except Exception as e:
                print(f"Error forcefully stopping {filename} (PID: {pid}): {e}")
                bot.send_message(ADMIN_ID, f"⚠️ تحذير أمني - فشل إيقاف البوت: فشل إيقاف البوت {filename} تلقائياً بسبب تجاوز الموارد")

            ban_user_db(user_id, f"Resource abuse: {reason}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
            add_security_log(user_id, "resource_abuse", f"Filename: {filename}, Reason: {reason}, PID: {pid}")
            
            bot.send_message(user_id, f"عذرًا، تم إيقاف بوتك {filename} وحظرك مؤقتًا (لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة) بسبب تجاوزه حدود الموارد المسموح بها: {reason}. يرجى مراجعة كود بوتك.")
            bot.send_message(ADMIN_ID, f"⚠️ تحذير أمني - إساءة استخدام موارد: تم إيقاف البوت {filename} وحظر مالكه {user_id} مؤقتًا بسبب {reason}")

# --- 7. الأوامر الأساسية للمستخدمين ---
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    username = message.from_user.username if message.from_user.username else f"id_{user_id}"
    register_user(user_id, username)

    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        if user_data['temp_ban_until'] and user_data['temp_ban_until'] > datetime.now():
            remaining_time = user_data['temp_ban_until'] - datetime.now()
            bot.send_message(message.chat.id, f"عذرًا، أنت محظور مؤقتًا حتى: {user_data['temp_ban_until'].strftime('%Y-%m-%d %H:%M:%S')} (المتبقي: {str(remaining_time).split('.')[0]}). السبب: {user_data['ban_reason']}")
        else:
            if user_data['temp_ban_until']:
                unban_user_db(user_id)
                bot.send_message(message.chat.id, "تم فك الحظر عنك تلقائياً. أهلاً بك مرة أخرى!")
                add_activity_log(ADMIN_ID, "auto_unban", f"User {user_id} unbanned automatically.")
            else:
                bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return

    markup = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
    
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        btn_check_sub = types.KeyboardButton('التحقق من الاشتراك ✅')
        markup.add(btn_check_sub)
        welcome_message = f"""
أهلاً بك في بوت رفع واستضافة بوتات بايثون

للبدء، يرجى الاشتراك في القناة التالية والضغط على "التحقق من الاشتراك":
{REQUIRED_CHANNEL_ID}

بعد الاشتراك، اضغط على الزر أدناه.
"""
        bot.send_message(message.chat.id, welcome_message, reply_markup=markup)
    else:
        btn_upload = types.KeyboardButton('رفع ملف ⬆️')
        btn_my_bots = types.KeyboardButton('بوتاتي 🤖')
        btn_help = types.KeyboardButton('المساعدة ❓')
        markup.add(btn_upload, btn_my_bots, btn_help)
        welcome_message = """
أهلاً بك في بوت رفع واستضافة بوتات بايثون

🎯 مهام البوت:
البوت مخصص لرفع واستضافة بوتات بايثون (.py) فقط.

🚀 كيفية الاستخدام:
* استخدم الأزرار للتنقل.
* ارفع ملفك (يجب أن يكون بصيغة .py).

للمساعدة:
* اكتب /help لعرض الشروط.
"""
        bot.send_message(message.chat.id, welcome_message, reply_markup=markup)
        add_activity_log(user_id, "start_command", "User started bot")

@bot.message_handler(func=lambda message: message.text == 'التحقق من الاشتراك ✅')
def check_subscription_button(message):
    user_id = message.from_user.id
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return

    if is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        markup = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
        btn_upload = types.KeyboardButton('رفع ملف ⬆️')
        btn_my_bots = types.KeyboardButton('بوتاتي 🤖')
        btn_help = types.KeyboardButton('المساعدة ❓')
        markup.add(btn_upload, btn_my_bots, btn_help)
        bot.send_message(message.chat.id, "✅ تم التحقق من اشتراكك بنجاح! يمكنك الآن استخدام البوت.", reply_markup=markup)
        add_activity_log(user_id, "checked_subscription", "User confirmed subscription")
    else:
        markup = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
        btn_check_sub = types.KeyboardButton('التحقق من الاشتراك ✅')
        markup.add(btn_check_sub)
        bot.send_message(message.chat.id, f"""
❌ لم يتم التحقق من اشتراكك. يرجى التأكد من الاشتراك في القناة التالية ثم الضغط على "التحقق من الاشتراك":
{REQUIRED_CHANNEL_ID}
""", reply_markup=markup)

@bot.message_handler(func=lambda message: message.text == 'رفع ملف ⬆️')
def ask_for_file(message):
    user_id = message.from_user.id
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return
    
    current_bots_count = get_user_bot_count(user_id)
    if current_bots_count >= MAX_BOTS_PER_USER:
        bot.send_message(message.chat.id, f"عذرًا، لقد وصلت إلى الحد الأقصى من البوتات المستضافة ({MAX_BOTS_PER_USER}). يرجى إيقاف/حذف بوت حالي لرفع بوت جديد.")
        return

    user_states[message.chat.id] = 'awaiting_file'
    bot.send_message(message.chat.id, "الرجاء إرسال ملف البايثون (بصيغة .py) الذي ترغب في رفعه واستضافته.")
    add_activity_log(user_id, "request_file_upload", "User requested to upload a file")

@bot.message_handler(content_types=['document'], func=lambda message: user_states.get(message.chat.id) == 'awaiting_file')
def handle_document(message):
    user_id = message.from_user.id
    username = message.from_user.username if message.from_user.username else f"id_{user_id}"
    register_user(user_id, username)

    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        user_states[message.chat.id] = None
        return
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        user_states[message.chat.id] = None
        return

    if not message.document.file_name.endswith('.py'):
        bot.send_message(message.chat.id, "عذرًا، يجب أن يكون الملف بصيغة .py فقط. الرجاء إعادة المحاولة.")
        user_states[message.chat.id] = None
        return
    
    file_name = message.document.file_name
    file_path = os.path.join(UPLOADED_BOTS_DIR, file_name)

    if os.path.exists(file_path):
        bot.send_message(message.chat.id, "ملف بهذا الاسم موجود بالفعل. يرجى تغيير اسم ملفك وإعادة المحاولة.")
        user_states[message.chat.id] = None
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        if len(downloaded_file) > MAX_FILE_SIZE_MB * 1024 * 1024:
            ban_user_db(user_id, f"File size ({len(downloaded_file)/(1024*1024):.2f}MB) exceeded limit ({MAX_FILE_SIZE_MB}MB)", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
            add_security_log(user_id, "file_size_exceeded", f"Filename: {file_name}, Size: {len(downloaded_file)} bytes")
            bot.send_message(message.chat.id, f"حجم الملف كبير جداً. تم حظرك تلقائياً (لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة) بسبب انتهاك شروط الاستخدام. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
            bot.send_message(ADMIN_ID, f"⚠️ تحذير أمني - حجم ملف كبير: تم حظر المستخدم {user_id} بسبب محاولة رفع ملف بحجم كبير جداً ({len(downloaded_file)} بايت)")
            user_states[message.chat.id] = None
            return

        with open(file_path, 'wb') as new_file:
            new_file.write(downloaded_file)

        is_malicious, detected_pattern = analyze_for_malicious_code(file_path)
        if is_malicious:
            ban_user_db(user_id, f"Detected malicious pattern: {detected_pattern}", is_temp=True, duration_minutes=SECURITY_BAN_DURATION_MINUTES)
            os.remove(file_path)
            add_security_log(user_id, "malicious_code_detected", f"Filename: {file_name}, Pattern: {detected_pattern}")
            
            security_failures[user_id]['count'] += 1
            security_failures[user_id]['last_failure'] = datetime.now()
            
            bot.send_message(message.chat.id, f"تم اكتشاف محتوى غير آمن في ملفك ({detected_pattern}). تم حظرك من استخدام البوت تلقائيًا (لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة) بسبب انتهاك شروط الاستخدام. يرجى التواصل مع المطور لفك الحظر: @llllllIlIlIlIlIlIlIl")
            bot.send_message(ADMIN_ID, f"⚠️ تحذير أمني - كود خبيث: تم حظر المستخدم {user_id} مؤقتاً بسبب محاولة رفع ملف يحتوي على محتوى مشبوه ({detected_pattern}). تم حذف الملف: {file_name}")
            
            if security_failures[user_id]['count'] >= SECURITY_FAILURE_THRESHOLD:
                ban_user_db(user_id, f"Repeated security violations (Malicious code: {detected_pattern})", is_temp=False)
                bot.send_message(user_id, "لقد تجاوزت عدد محاولات رفع الأكواد الضارة المسموح بها. تم حظرك بشكل دائم. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
                bot.send_message(ADMIN_ID, f"🚨 تحذير أمني - حظر دائم: المستخدم {user_id} تم حظره دائمًا بسبب تكرار انتهاكات الأمان.")
            
            user_states[message.chat.id] = None
            return

        bot.send_message(message.chat.id, f"تم استقبال ملفك بنجاح: {file_name}. جاري الاستضافة...")
        add_activity_log(user_id, "file_uploaded", f"Filename: {file_name}")

        if file_name in running_processes:
            terminate_process(file_name)
            bot.send_message(message.chat.id, f"تم إيقاف الإصدار السابق من {file_name} لتحديثه.")
            add_activity_log(user_id, "bot_stopped_for_update", f"Filename: {file_name}")
        
        bot_stdout_path = os.path.join(UPLOADED_BOTS_DIR, f"{file_name}.stdout")
        bot_stderr_path = os.path.join(UPLOADED_BOTS_DIR, f"{file_name}.stderr")

        with open(bot_stdout_path, 'w') as stdout_file, open(bot_stderr_path, 'w') as stderr_file:
            try:
                process = subprocess.Popen(
                    ['python3', file_name],
                    cwd=UPLOADED_BOTS_DIR,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    close_fds=True
                )
                running_processes[file_name] = process
                add_hosted_bot_db(user_id, file_name, process.pid, 'running')
                
                time.sleep(3)

                if process.poll() is None:
                    bot.send_message(message.chat.id, f"تم استضافة البوت {file_name} بنجاح وسيظل يعمل بشكل دائم! ✅")
                    add_activity_log(user_id, "bot_started", f"Filename: {file_name}, PID: {process.pid}")
                else:
                    with open(bot_stderr_path, 'r') as err_f:
                        stderr_output = err_f.read().strip()
                    bot.send_message(message.chat.id, f"حدث خطأ أثناء تشغيل البوت {file_name}:\n{stderr_output[:1000]}...")
                    bot.send_message(ADMIN_ID, f"⚠️ خطأ تشغيل بوت: فشل تشغيل البوت {file_name} للمستخدم {user_id}")
                    update_hosted_bot_status_db(file_name, 'error', error_log=stderr_output[:1000])
                    add_activity_log(user_id, "bot_start_failed", f"Filename: {file_name}, Error: {stderr_output[:200]}")
                    if file_name in running_processes:
                        del running_processes[file_name]

            except Exception as e:
                bot.send_message(message.chat.id, f"حدث خطأ غير متوقع أثناء الاستضافة: {e}")
                bot.send_message(ADMIN_ID, f"⚠️ خطأ عام في الاستضافة: حدث خطأ غير متوقع للمستخدم {user_id} أثناء استضافة {file_name}")
                update_hosted_bot_status_db(file_name, 'error', error_log=str(e))

    except Exception as e:
        bot.send_message(message.chat.id, f"حدث خطأ غير متوقع أثناء معالجة ملفك: {e}")
        bot.send_message(ADMIN_ID, f"⚠️ خطأ في معالجة الملف: حدث خطأ غير متوقع للمستخدم {user_id}: {e}")
        add_activity_log(user_id, "file_processing_error", f"Error: {e}")

    user_states[message.chat.id] = None

@bot.message_handler(func=lambda message: message.text == 'بوتاتي 🤖')
def list_user_bots(message):
    user_id = message.from_user.id
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return

    bots_data = get_all_hosted_bots_db(user_id)
    if bots_data:
        bots_list_msg = "بوتاتك المستضافة:\n"
        for i, (filename, status, _, _, last_started, start_count) in enumerate(bots_data):
            start_time_str = datetime.strptime(last_started, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M') if last_started else 'N/A'
            bots_list_msg += f"{i+1}. {filename}\n   الحالة: {status} | بدأ: {start_time_str} | مرات التشغيل: {start_count}\n"
        
        markup = types.InlineKeyboardMarkup(row_width=2)
        for filename_in_data, status, _, _, _, _ in bots_data:
            btn_stop = types.InlineKeyboardButton(f"إيقاف {filename_in_data[:10]}", callback_data=f"user_stop_{filename_in_data}")
            btn_delete = types.InlineKeyboardButton(f"حذف {filename_in_data[:10]}", callback_data=f"user_delete_{filename_in_data}")
            markup.add(btn_stop, btn_delete)
        
        bot.send_message(message.chat.id, bots_list_msg, reply_markup=markup)
    else:
        bot.send_message(message.chat.id, "ليس لديك أي بوتات مستضافة حاليًا. قم برفع ملف جديد!")
    add_activity_log(user_id, "viewed_my_bots", "")

@bot.callback_query_handler(func=lambda call: call.data.startswith('user_'))
def user_bot_actions_callback(call):
    user_id = call.from_user.id
    action = call.data.split('_')[1]
    filename = '_'.join(call.data.split('_')[2:])

    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.answer_callback_query(call.id, "عذرًا، أنت محظور من استخدام هذا البوت.")
        return
    
    bot_info = db_execute("SELECT user_id, status FROM hosted_bots WHERE filename = ?", (filename,), fetch_one=True)
    if not bot_info or bot_info[0] != user_id:
        bot.answer_callback_query(call.id, "ليس لديك صلاحية للتحكم بهذا البوت.")
        return

    if action == 'stop':
        if terminate_process(filename):
            bot.send_message(call.message.chat.id, f"تم إيقاف البوت {filename} بنجاح.")
            add_activity_log(user_id, "user_stopped_bot", f"Filename: {filename}")
        else:
            bot.send_message(call.message.chat.id, f"البوت {filename} ليس قيد التشغيل أو حدث خطأ أثناء الإيقاف.")
        bot.answer_callback_query(call.id)
    elif action == 'delete':
        if terminate_process(filename):
            bot.send_message(call.message.chat.id, f"تم إيقاف البوت {filename} قبل حذفه.")
        try:
            os.remove(os.path.join(UPLOADED_BOTS_DIR, filename))
            if os.path.exists(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout")):
                os.remove(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout"))
            if os.path.exists(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr")):
                os.remove(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr"))

            delete_hosted_bot_db(filename)
            bot.send_message(call.message.chat.id, f"تم حذف البوت {filename} بنجاح من الخادم وقاعدة البيانات.")
            add_activity_log(user_id, "user_deleted_bot", f"Filename: {filename}")
        except Exception as e:
            bot.send_message(call.message.chat.id, f"حدث خطأ أثناء حذف البوت {filename}: {e}")
            bot.send_message(ADMIN_ID, f"⚠️ خطأ مطور - حذف بوت المستخدم: المستخدم {user_id} حاول حذف {filename} وحدث خطأ: {e}")
        bot.answer_callback_query(call.id)

@bot.message_handler(commands=['help'])
def send_help(message):
    user_id = message.from_user.id
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return
    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID):
        send_welcome(message)
        return

    help_message = f"""
للمساعدة والشروط:
* رفع ملف: اضغط على زر "رفع ملف ⬆️" ثم أرسل ملف البايثون الخاص بك (يجب أن يكون بصيغة .py)
* عدد البوتات: يمكن لكل مستخدم استضافة {MAX_BOTS_PER_USER} بوت كحد أقصى
* الاستضافة: سيتم استضافة بوتك وتشغيله بشكل دائم
* الحماية: يتم فحص الملفات المرفوعة للكشف عن أي أكواد ضارة
    * أي محاولة لرفع كود خبيث ستؤدي إلى حظرك المؤقت (لمدة {SECURITY_BAN_DURATION_MINUTES} دقيقة)
    * تكرار المحاولات سيؤدي إلى حظرك الدائم
* الدعم الفني: في حال واجهت أي مشاكل يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl
"""
    bot.send_message(message.chat.id, help_message)
    add_activity_log(user_id, "requested_help", "")


# --- 8. أوامر المطور (الأدمن) ---
@bot.message_handler(commands=['admin_panel'])
def admin_panel(message):
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "ليس لديك صلاحيات للوصول إلى لوحة تحكم المطور.")
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    btn_list_bots = types.InlineKeyboardButton('البوتات المستضافة', callback_data='admin_list_bots')
    btn_stop_bot = types.InlineKeyboardButton('إيقاف بوت', callback_data='admin_stop_bot')
    btn_delete_bot = types.InlineKeyboardButton('حذف بوت', callback_data='admin_delete_bot')
    btn_ban_user = types.InlineKeyboardButton('حظر مستخدم', callback_data='admin_ban_user')
    btn_unban_user = types.InlineKeyboardButton('فك حظر مستخدم', callback_data='admin_unban_user')
    btn_list_banned = types.InlineKeyboardButton('قائمة المحظورين', callback_data='admin_list_banned')
    btn_view_file = types.InlineKeyboardButton('عرض ملف', callback_data='admin_view_file')
    btn_exec_command = types.InlineKeyboardButton('تنفيذ أمر', callback_data='admin_exec_command')
    btn_reboot_all = types.InlineKeyboardButton('إعادة تشغيل الكل', callback_data='admin_reboot_all_bots')
    btn_logs_activity = types.InlineKeyboardButton('سجل النشاط', callback_data='admin_logs_activity')
    btn_logs_security = types.InlineKeyboardButton('سجل الأمان', callback_data='admin_logs_security')
    btn_stats = types.InlineKeyboardButton('الإحصائيات', callback_data='admin_stats')
    btn_cleanup = types.InlineKeyboardButton('تنظيف البوتات', callback_data='admin_cleanup_stopped_bots')
    
    markup.add(btn_list_bots, btn_stop_bot, btn_delete_bot, btn_ban_user, btn_unban_user, btn_list_banned, btn_view_file, btn_exec_command, btn_reboot_all, btn_logs_activity, btn_logs_security, btn_stats, btn_cleanup)
    
    bot.send_message(message.chat.id, "لوحة تحكم المطور:\nاختر الإجراء المطلوب:", reply_markup=markup)
    add_activity_log(message.from_user.id, "admin_panel_accessed", "")

@bot.callback_query_handler(func=lambda call: call.data.startswith('admin_'))
def admin_callback_query(call):
    if not is_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "ليس لديك صلاحيات.")
        return

    action = call.data.replace('admin_', '')
    add_activity_log(call.from_user.id, f"admin_action_{action}", "")

    if action == 'list_bots':
        bots_data = get_all_hosted_bots_db()
        if bots_data:
            bots_status = "البوتات المستضافة حاليًا:\n"
            for filename, status, user_id, pid, last_started, start_count in bots_data:
                username = get_user_data(user_id)['username'] if get_user_data(user_id) else "N/A"
                start_time_str = datetime.strptime(last_started, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M') if last_started else 'N/A'
                bots_status += f"📁 {filename}\n   الحالة: {status} | PID: {pid if pid else 'N/A'} | المستخدم: {username} (ID: {user_id})\n   بدأ: {start_time_str} | مرات التشغيل: {start_count}\n\n"
            if len(bots_status) > 4000:
                parts = [bots_status[i:i+4000] for i in range(0, len(bots_status), 4000)]
                for part in parts:
                    bot.send_message(call.message.chat.id, part)
            else:
                bot.send_message(call.message.chat.id, bots_status)
        else:
            bot.send_message(call.message.chat.id, "لا توجد بوتات مستضافة حاليًا.")
        bot.answer_callback_query(call.id)

    elif action == 'stop_bot':
        bot.send_message(call.message.chat.id, "الرجاء إرسال اسم الملف الخاص بالبوت الذي تريد إيقافه (مثال: my_bot.py)")
        user_states[call.from_user.id] = 'awaiting_admin_stop_bot_filename'
        bot.answer_callback_query(call.id)

    elif action == 'delete_bot':
        bot.send_message(call.message.chat.id, "الرجاء إرسال اسم الملف الخاص بالبوت الذي تريد حذفه (مثال: my_bot.py)")
        user_states[call.from_user.id] = 'awaiting_admin_delete_bot_filename'
        bot.answer_callback_query(call.id)
    
    elif action == 'ban_user':
        bot.send_message(call.message.chat.id, "الرجاء إرسال ID المستخدم الذي تريد حظره")
        user_states[call.from_user.id] = 'awaiting_admin_ban_user_id'
        bot.answer_callback_query(call.id)

    elif action == 'unban_user':
        bot.send_message(call.message.chat.id, "الرجاء إرسال ID المستخدم الذي تريد فك حظره")
        user_states[call.from_user.id] = 'awaiting_admin_unban_user_id'
        bot.answer_callback_query(call.id)

    elif action == 'list_banned':
        banned_users = get_banned_users_db()
        if banned_users:
            banned_list = "المستخدمون المحظورون:\n"
            for user_id_banned, username, reason, temp_ban_until in banned_users:
                ban_type = "مؤقت" if temp_ban_until else "دائم"
                until_msg = f" (حتى: {temp_ban_until})" if temp_ban_until else ""
                banned_list += f"👤 {user_id_banned} (Username: {username})\n   النوع: {ban_type} | السبب: {reason}{until_msg}\n\n"
            if len(banned_list) > 4000:
                parts = [banned_list[i:i+4000] for i in range(0, len(banned_list), 4000)]
                for part in parts:
                    bot.send_message(call.message.chat.id, part)
            else:
                bot.send_message(call.message.chat.id, banned_list)
        else:
            bot.send_message(call.message.chat.id, "لا يوجد مستخدمون محظورون حاليًا.")
        bot.answer_callback_query(call.id)

    elif action == 'view_file':
        bot.send_message(call.message.chat.id, "الرجاء إرسال اسم الملف الذي تريد عرض محتواه (مثال: my_bot.py)")
        user_states[call.from_user.id] = 'awaiting_admin_view_file_filename'
        bot.answer_callback_query(call.id)

    elif action == 'exec_command':
        bot.send_message(call.message.chat.id, "الرجاء إرسال الأمر الذي تريد تنفيذه في الـ shell (مثال: ls -l, df -h)")
        user_states[call.from_user.id] = 'awaiting_admin_shell_command'
        bot.answer_callback_query(call.id)

    elif action == 'reboot_all_bots':
        bot.send_message(call.message.chat.id, "جاري إعادة تشغيل جميع البوتات المستضافة...")
        bots_data = get_all_hosted_bots_db()
        rebooted_count = 0
        for filename, status, user_id, pid, _, _ in bots_data:
            if terminate_process(filename):
                try:
                    file_path = os.path.join(UPLOADED_BOTS_DIR, filename)
                    bot_stdout_path = os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout")
                    bot_stderr_path = os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr")
                    with open(bot_stdout_path, 'w') as stdout_file, open(bot_stderr_path, 'w') as stderr_file:
                        process = subprocess.Popen(
                            ['python3', file_path],
                            stdout=stdout_file,
                            stderr=stderr_file,
                            close_fds=True
                        )
                        running_processes[filename] = process
                        update_hosted_bot_status_db(filename, 'running', process.pid)
                        rebooted_count += 1
                except Exception as e:
                    bot.send_message(ADMIN_ID, f"⚠️ خطأ في إعادة تشغيل بوت: فشل إعادة تشغيل البوت {filename} للمستخدم {user_id}")
                    update_hosted_bot_status_db(filename, 'error', error_log=str(e))
            else:
                 bot.send_message(ADMIN_ID, f"⚠️ خطأ في إعادة تشغيل بوت: فشل إيقاف البوت {filename} قبل إعادة تشغيله")

        bot.send_message(call.message.chat.id, f"تمت محاولة إعادة تشغيل {rebooted_count} بوت بنجاح.")
        bot.answer_callback_query(call.id)
    
    elif action == 'logs_activity':
        logs = db_execute("SELECT timestamp, user_id, action, details FROM activity_logs ORDER BY timestamp DESC LIMIT 50", fetch_all=True)
        if logs:
            log_message = "آخر 50 سجل نشاط:\n"
            for timestamp, user_id, action, details in logs:
                username = get_user_data(user_id)['username'] if get_user_data(user_id) else "N/A"
                log_message += f"🕒 {timestamp} | 👤 {user_id} ({username}) | 📝 {action}: {details}\n"
            if len(log_message) > 4000:
                parts = [log_message[i:i+4000] for i in range(0, len(log_message), 4000)]
                for part in parts:
                    bot.send_message(call.message.chat.id, part)
            else:
                bot.send_message(call.message.chat.id, log_message)
        else:
            bot.send_message(call.message.chat.id, "لا توجد سجلات نشاط.")
        bot.answer_callback_query(call.id)

    elif action == 'logs_security':
        logs = db_execute("SELECT timestamp, user_id, action, details FROM security_logs ORDER BY timestamp DESC LIMIT 50", fetch_all=True)
        if logs:
            log_message = "آخر 50 سجل أمان:\n"
            for timestamp, user_id, action, details in logs:
                username = get_user_data(user_id)['username'] if get_user_data(user_id) else "N/A"
                log_message += f"🕒 {timestamp} | 👤 {user_id} ({username}) | 🚨 {action}: {details}\n"
            if len(log_message) > 4000:
                parts = [log_message[i:i+4000] for i in range(0, len(log_message), 4000)]
                for part in parts:
                    bot.send_message(call.message.chat.id, part)
            else:
                bot.send_message(call.message.chat.id, log_message)
        else:
            bot.send_message(call.message.chat.id, "لا توجد سجلات أمان.")
        bot.answer_callback_query(call.id)
    
    elif action == 'stats':
        total_users = db_execute("SELECT COUNT(*) FROM users", fetch_one=True)[0]
        banned_users = db_execute("SELECT COUNT(*) FROM users WHERE is_banned = 1", fetch_one=True)[0]
        total_bots = db_execute("SELECT COUNT(*) FROM hosted_bots", fetch_one=True)[0]
        running_bots = db_execute("SELECT COUNT(*) FROM hosted_bots WHERE status = 'running'", fetch_one=True)[0]

        total_size_bytes = 0
        for dirpath, dirnames, filenames in os.walk(UPLOADED_BOTS_DIR):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if not os.path.islink(fp):
                    total_size_bytes += os.path.getsize(fp)
        
        stats_message = f"""
📊 إحصائيات النظام:
👥 إجمالي المستخدمين: {total_users}
🚫 المستخدمون المحظورون: {banned_users}
🤖 إجمالي البوتات المستضافة: {total_bots}
⚡ البوتات العاملة حاليًا: {running_bots}
💾 المساحة المستخدمة: {total_size_bytes / (1024 * 1024):.2f} MB
"""
        bot.send_message(call.message.chat.id, stats_message)
        bot.answer_callback_query(call.id)
    
    elif action == 'cleanup_stopped_bots':
        stopped_bots = db_execute("SELECT filename FROM hosted_bots WHERE status = 'stopped' OR status = 'error'", fetch_all=True)
        cleaned_count = 0
        if stopped_bots:
            for bot_file_tuple in stopped_bots:
                filename = bot_file_tuple[0]
                file_path = os.path.join(UPLOADED_BOTS_DIR, filename)
                bot_stdout_path = os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout")
                bot_stderr_path = os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr")
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    if os.path.exists(bot_stdout_path):
                        os.remove(bot_stdout_path)
                    if os.path.exists(bot_stderr_path):
                        os.remove(bot_stderr_path)

                    delete_hosted_bot_db(filename)
                    cleaned_count += 1
                    add_activity_log(call.from_user.id, "admin_cleanup_bot", f"Cleaned up stopped/error bot: {filename}")
                except Exception as e:
                    bot.send_message(ADMIN_ID, f"⚠️ خطأ مطور - تنظيف: فشل حذف الملف {filename} أثناء التنظيف")
            bot.send_message(call.message.chat.id, f"تم تنظيف {cleaned_count} بوت متوقف/بخطأ بنجاح.")
        else:
            bot.send_message(call.message.chat.id, "لا توجد بوتات متوقفة أو بها أخطاء للتنظيف.")
        bot.answer_callback_query(call.id)

# --- 9. معالجة مدخلات المطور ---
@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_stop_bot_filename')
def handle_admin_stop_bot_filename(message):
    filename = message.text.strip()
    if terminate_process(filename):
        bot.send_message(message.chat.id, f"تم إيقاف البوت {filename} بنجاح.")
        add_activity_log(message.from_user.id, "admin_stopped_bot", f"Filename: {filename}")
    else:
        bot.send_message(message.chat.id, f"البوت {filename} ليس قيد التشغيل أو غير موجود.")
    user_states[message.from_user.id] = None

@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_delete_bot_filename')
def handle_admin_delete_bot_filename(message):
    filename = message.text.strip()
    file_path = os.path.join(UPLOADED_BOTS_DIR, filename)

    if os.path.exists(file_path):
        if terminate_process(filename):
            bot.send_message(message.chat.id, f"تم إيقاف البوت {filename} قبل الحذف.")
        
        try:
            os.remove(file_path)
            if os.path.exists(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout")):
                os.remove(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stdout"))
            if os.path.exists(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr")):
                os.remove(os.path.join(UPLOADED_BOTS_DIR, f"{filename}.stderr"))

            delete_hosted_bot_db(filename)
            bot.send_message(message.chat.id, f"تم حذف البوت {filename} بنجاح من الخادم وقاعدة البيانات.")
            add_activity_log(message.from_user.id, "admin_deleted_bot", f"Filename: {filename}")
        except Exception as e:
            bot.send_message(message.chat.id, f"حدث خطأ أثناء حذف البوت {filename}: {e}")
            bot.send_message(ADMIN_ID, f"⚠️ خطأ مطور - حذف بوت: فشل حذف الملف {filename}")
    else:
        bot.send_message(message.chat.id, f"الملف {filename} غير موجود في مجلد البوتات المستضافة.")
    user_states[message.from_user.id] = None

@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_ban_user_id')
def handle_admin_ban_user_id(message):
    try:
        user_id_to_ban = int(message.text.strip())
        if user_id_to_ban == ADMIN_ID:
            bot.send_message(message.chat.id, "لا يمكنك حظر نفسك يا مطور!")
        else:
            ban_user_db(user_id_to_ban, "تم الحظر يدويا بواسطة المطور.")
            bot.send_message(message.chat.id, f"تم حظر المستخدم ذو الـ ID {user_id_to_ban} بنجاح (حظر دائم).")
            add_activity_log(message.from_user.id, "admin_banned_user", f"User ID: {user_id_to_ban}")
            try:
                bot.send_message(user_id_to_ban, "لقد تم حظرك من استخدام هذا البوت بواسطة المطور. يرجى التواصل معه لفك الحظر: @llllllIlIlIlIlIlIlIl")
            except Exception as e:
                print(f"Failed to send ban message to user {user_id_to_ban}: {e}")
                bot.send_message(message.chat.id, f"لم أتمكن من إرسال رسالة للمستخدم المحظور (قد يكون قد حظر البوت)")
    except ValueError:
        bot.send_message(message.chat.id, "معرف المستخدم غير صالح. يرجى إدخال رقم صحيح.")
    user_states[message.from_user.id] = None

@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_unban_user_id')
def handle_admin_unban_user_id(message):
    try:
        user_id_to_unban = int(message.text.strip())
        if unban_user_db(user_id_to_unban):
            bot.send_message(message.chat.id, f"تم فك حظر المستخدم ذو الـ ID {user_id_to_unban} بنجاح.")
            add_activity_log(message.from_user.id, "admin_unbanned_user", f"User ID: {user_id_to_unban}")
            try:
                bot.send_message(user_id_to_unban, "تم فك الحظر عنك. يمكنك الآن استخدام البوت.")
            except Exception as e:
                print(f"Failed to send unban message to user {user_id_to_unban}: {e}")
                bot.send_message(message.chat.id, f"لم أتمكن من إرسال رسالة للمستخدم بعد فك الحظر (قد يكون قد حظر البوت)")
        else:
            bot.send_message(message.chat.id, f"المستخدم ذو الـ ID {user_id_to_unban} ليس محظورًا أصلاً.")
    except ValueError:
        bot.send_message(message.chat.id, "معرف المستخدم غير صالح. يرجى إدخال رقم صحيح.")
    user_states[message.from_user.id] = None

@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_view_file_filename')
def handle_admin_view_file_filename(message):
    filename = message.text.strip()
    file_path = os.path.join(UPLOADED_BOTS_DIR, filename)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                if len(content) > 4000:
                    bot.send_message(message.chat.id, f"محتوى الملف {filename} (مقتطع):\n{content[:3900]}...")
                else:
                    bot.send_message(message.chat.id, f"محتوى الملف {filename}:\n{content}")
            add_activity_log(message.from_user.id, "admin_viewed_file", f"Filename: {filename}")
        except Exception as e:
            bot.send_message(message.chat.id, f"حدث خطأ أثناء قراءة الملف {filename}: {e}")
            bot.send_message(ADMIN_ID, f"⚠️ خطأ مطور - قراءة ملف: فشلت قراءة {filename}")
    else:
        bot.send_message(message.chat.id, f"الملف {filename} غير موجود أو ليس ملفًا صالحًا في مجلد البوتات المستضافة.")
    user_states[message.from_user.id] = None

@bot.message_handler(func=lambda message: is_admin(message.from_user.id) and user_states.get(message.from_user.id) == 'awaiting_admin_shell_command')
def handle_admin_shell_command(message):
    command = message.text.strip()
    if not command:
        bot.send_message(message.chat.id, "لم يتم إدخال أمر. يرجى إرسال الأمر الذي تريد تنفيذه.")
        user_states[message.from_user.id] = None
        return
        
    try:
        process_result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False, 
            timeout=30
        )
        output = process_result.stdout
        error = process_result.stderr

        response_message = f"مخرجات الأمر {command}:\n{output[:3000] if output else 'لا توجد مخرجات'}"
        
        if error:
            response_message += f"\nالأخطاء (إن وجدت):\n{error[:1000]}"
        
        if len(response_message) > 4000:
            bot.send_message(message.chat.id, response_message[:4000] + "\n...")
        else:
            bot.send_message(message.chat.id, response_message)
        add_activity_log(message.from_user.id, "admin_executed_shell_command", f"Command: {command}")

    except subprocess.TimeoutExpired:
        bot.send_message(message.chat.id, f"تنفيذ الأمر {command} تجاوز المهلة المحددة (30 ثانية)")
        bot.send_message(ADMIN_ID, f"⚠️ تنبيه مطور - أمر تجاوز المهلة: الأمر {command} تجاوز المهلة عند تنفيذه")
        add_activity_log(message.from_user.id, "admin_shell_command_timeout", f"Command: {command}")
    except Exception as e:
        bot.send_message(message.chat.id, f"حدث خطأ أثناء تنفيذ الأمر: {e}")
        bot.send_message(ADMIN_ID, f"⚠️ خطأ مطور - تنفيذ أمر: حدث خطأ أثناء تنفيذ الأمر {command}")
        add_activity_log(message.from_user.id, "admin_shell_command_error", f"Command: {command}, Error: {e}")
    
    user_states[message.from_user.id] = None

# --- 10. التعامل مع الرسائل النصية الأخرى ---
@bot.message_handler(func=lambda message: True)
def echo_all(message):
    user_id = message.from_user.id
    user_data = get_user_data(user_id)
    if user_data and user_data['is_banned']:
        if user_data['temp_ban_until'] and user_data['temp_ban_until'] > datetime.now():
            remaining_time = user_data['temp_ban_until'] - datetime.now()
            bot.send_message(message.chat.id, f"عذرًا، أنت محظور مؤقتًا حتى: {user_data['temp_ban_until'].strftime('%Y-%m-%d %H:%M:%S')} (المتبقي: {str(remaining_time).split('.')[0]}). السبب: {user_data['ban_reason']}")
        else:
            if user_data['temp_ban_until']:
                unban_user_db(user_id)
                bot.send_message(message.chat.id, "تم فك الحظر عنك تلقائياً. أهلاً بك مرة أخرى!")
                add_activity_log(ADMIN_ID, "auto_unban", f"User {user_id} unbanned automatically.")
            else:
                bot.send_message(message.chat.id, f"عذرًا، أنت محظور من استخدام هذا البوت بسبب: {user_data['ban_reason']}. يرجى التواصل مع المطور: @llllllIlIlIlIlIlIlIl")
        return

    if is_admin(user_id) and user_states.get(user_id) in [
        'awaiting_admin_stop_bot_filename', 'awaiting_admin_delete_bot_filename',
        'awaiting_admin_ban_user_id', 'awaiting_admin_unban_user_id',
        'awaiting_admin_view_file_filename', 'awaiting_admin_shell_command'
    ]:
        return

    if not is_subscribed(user_id, REQUIRED_CHANNEL_ID) and message.text not in ['التحقق من الاشتراك ✅', '/start']:
        send_welcome(message)
        return

    if user_states.get(message.chat.id) != 'awaiting_file':
        bot.send_message(message.chat.id, "الرجاء استخدام الأزرار المتاحة للتنقل أو كتابة /help للمساعدة. للمطور: /admin_panel")

# --- 11. تشغيل المراقبة في الخلفية ---
def run_monitor():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(monitor_bot_resources())

# --- 12. التشغيل الرئيسي ---
if __name__ == '__main__':
    if not API_TOKEN:
        print("خطأ: لم يتم تعيين 'BOT_TOKEN'")
        exit(1)

    init_db()

    print("جاري تهيئة البوتات المستضافة...")
    all_hosted_bots = get_all_hosted_bots_db()
    for filename, status, user_id, pid, last_started, start_count in all_hosted_bots:
        if status == 'running':
            update_hosted_bot_status_db(filename, 'stopped', error_log="Bot status reset on main app restart.")
            print(f"Bot {filename} status reset to 'stopped' due to restart.")

    print("بدء تشغيل مراقبة الموارد في الخيط الخلفي...")
    monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    monitor_thread.start()

    print("البوت بدأ العمل في وضع Polling...")
    print("البوت يعمل الآن! استخدم Ctrl+C لإيقافه.")
    print(f"👑 المطور: {ADMIN_ID} (@llllllIlIlIlIlIlIlIl)")
    
    try:
        bot.infinity_polling(timeout=60, long_polling_timeout=60)
    except KeyboardInterrupt:
        print("\nجاري إيقاف البوت...")
        for filename in list(running_processes.keys()):
            terminate_process(filename)
        print("تم إيقاف جميع البوتات المستضافة.")
    except Exception as e:
        print(f"حدث خطأ أثناء تشغيل البوت: {e}")