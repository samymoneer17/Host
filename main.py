import telebot
from telebot import types, apihelper
import os
import time
import subprocess
import threading
import random
import psutil
import ast
import re
import datetime
import statistics
import json
import sqlite3
from datetime import datetime, timedelta

# تفعيل الميدل وير قبل تهيئة البوت
apihelper.ENABLE_MIDDLEWARE = True

# تعيين توكن البوت كمتغير
BOT_TOKEN = '8156912979:AAHyLYBEM7GBOfFjvwFtJ9Cxkg4uEqxUFLY'

# اسم القناة
CHANNEL_USERNAME = '@pythonyemen1'

# معرف المالك
OWNER_ID = 7627857345

# قائمة الأدمن
ADMINS = [OWNER_ID]  # يمكن إضافة أكثر من أدمن

# مسار حفظ الملفات
UPLOAD_FOLDER = 'uploaded_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# قاعدة البيانات
DB_FILE = 'bot_database.db'

# لتخزين الملفات لكل مستخدم
user_files = {}

# لتخزين العمليات الجارية
running_processes = {}

# لتخزين معلومات سرعة الاستجابة
response_speed_info = {
    'last_check': None,
    'response_times': [],
    'avg_response_time': 0.15,
    'speed_category': 'M0.15',
    'min_response': float('inf'),
    'max_response': 0,
    'last_10_responses': []
}

# تحميل ClamAV بشكل مشروط (لتجنب الأخطاء)
try:
    import pyclamd
    cd = pyclamd.ClamdAgnostic()
    cd.ping()
    CLAMAV_AVAILABLE = True
    print("✅ ClamAV متاح للفحص")
except Exception as e:
    print(f"⚠️ ClamAV غير متاح: {e}")
    cd = None
    CLAMAV_AVAILABLE = False

# تهيئة قاعدة البيانات
def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # جدول القنوات الإجبارية
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS required_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT UNIQUE,
            channel_username TEXT,
            channel_name TEXT,
            added_by INTEGER,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # جدول المستخدمين المحظورين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            banned_by INTEGER,
            ban_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        )
    ''')
    
    # جدول الأدمن المساعدين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assistant_admins (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            added_by INTEGER,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            permissions TEXT DEFAULT 'basic'
        )
    ''')
    
    # جدول إحصائيات المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_active TIMESTAMP,
            message_count INTEGER DEFAULT 0,
            file_count INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()

# استدعاء تهيئة قاعدة البيانات
init_database()

# ========== دوال قسم الأدمن ==========

def is_admin(user_id):
    """التحقق إذا كان المستخدم أدمن"""
    return user_id in ADMINS or is_assistant_admin(user_id)

def is_assistant_admin(user_id):
    """التحقق إذا كان المستخدم أدمن مساعد"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM assistant_admins WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def add_required_channel(channel_id, channel_username, channel_name, added_by):
    """إضافة قناة إجبارية"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO required_channels 
            (channel_id, channel_username, channel_name, added_by) 
            VALUES (?, ?, ?, ?)
        ''', (channel_id, channel_username, channel_name, added_by))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في إضافة القناة: {e}")
        return False

def remove_required_channel(channel_id):
    """حذف قناة إجبارية"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM required_channels WHERE channel_id = ?', (channel_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في حذف القناة: {e}")
        return False

def get_required_channels():
    """الحصول على جميع القنوات الإجبارية"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM required_channels ORDER BY added_date DESC')
    channels = cursor.fetchall()
    conn.close()
    return channels

def ban_user(user_id, username, first_name, last_name, banned_by, reason=""):
    """حظر مستخدم"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO banned_users 
            (user_id, username, first_name, last_name, banned_by, reason) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, first_name, last_name, banned_by, reason))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في حظر المستخدم: {e}")
        return False

def unban_user(user_id):
    """فك حظر مستخدم"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM banned_users WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في فك حظر المستخدم: {e}")
        return False

def is_user_banned(user_id):
    """التحقق إذا كان المستخدم محظور"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM banned_users WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def get_banned_users():
    """الحصول على جميع المستخدمين المحظورين"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM banned_users ORDER BY ban_date DESC')
    users = cursor.fetchall()
    conn.close()
    return users

def add_assistant_admin(user_id, username, first_name, last_name, added_by):
    """إضافة أدمن مساعد"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO assistant_admins 
            (user_id, username, first_name, last_name, added_by) 
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, username, first_name, last_name, added_by))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في إضافة الأدمن المساعد: {e}")
        return False

def remove_assistant_admin(user_id):
    """إزالة أدمن مساعد"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM assistant_admins WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"خطأ في إزالة الأدمن المساعد: {e}")
        return False

def get_assistant_admins():
    """الحصول على جميع الأدمن المساعدين"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM assistant_admins ORDER BY added_date DESC')
    admins = cursor.fetchall()
    conn.close()
    return admins

def update_user_stats(user_id, username, first_name, last_name):
    """تحديث إحصائيات المستخدم"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # التحقق إذا كان المستخدم موجود
        cursor.execute('SELECT user_id FROM user_stats WHERE user_id = ?', (user_id,))
        if cursor.fetchone():
            # تحديث آخر نشاط
            cursor.execute('''
                UPDATE user_stats 
                SET last_active = CURRENT_TIMESTAMP, 
                    message_count = message_count + 1,
                    username = ?,
                    first_name = ?,
                    last_name = ?
                WHERE user_id = ?
            ''', (username, first_name, last_name, user_id))
        else:
            # إضافة مستخدم جديد
            cursor.execute('''
                INSERT INTO user_stats 
                (user_id, username, first_name, last_name, last_active, message_count) 
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
            ''', (user_id, username, first_name, last_name))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"خطأ في تحديث إحصائيات المستخدم: {e}")

def get_user_stats(user_id):
    """الحصول على إحصائيات مستخدم"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_stats WHERE user_id = ?', (user_id,))
    stats = cursor.fetchone()
    conn.close()
    return stats

def get_bot_statistics():
    """الحصول على إحصائيات البوت"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # عدد المستخدمين الإجمالي
    cursor.execute('SELECT COUNT(*) FROM user_stats')
    total_users = cursor.fetchone()[0]
    
    # عدد المستخدمين النشطين اليوم
    cursor.execute('SELECT COUNT(*) FROM user_stats WHERE last_active >= datetime("now", "-1 day")')
    active_today = cursor.fetchone()[0]
    
    # عدد المستخدمين النشطين هذا الأسبوع
    cursor.execute('SELECT COUNT(*) FROM user_stats WHERE last_active >= datetime("now", "-7 days")')
    active_week = cursor.fetchone()[0]
    
    # عدد الملفات المرفوعة
    total_files = sum(len(files) for files in user_files.values())
    
    # عدد المستخدمين المحظورين
    cursor.execute('SELECT COUNT(*) FROM banned_users')
    banned_users = cursor.fetchone()[0]
    
    # عدد الأدمن المساعدين
    cursor.execute('SELECT COUNT(*) FROM assistant_admins')
    assistant_admins = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_users': total_users,
        'active_today': active_today,
        'active_week': active_week,
        'total_files': total_files,
        'banned_users': banned_users,
        'assistant_admins': assistant_admins
    }

# ========== دوال السرعة ==========

def measure_response_speed():
    """قياس سرعة استجابة البوت"""
    try:
        start_time = time.time()
        test_id = f"speed_test_{int(time.time())}_{random.randint(1000, 9999)}"
        test_message = bot.send_message(OWNER_ID, f"⏱️ اختبار السرعة - {test_id}")
        end_time = time.time()
        response_time = end_time - start_time
        
        try:
            bot.delete_message(OWNER_ID, test_message.message_id)
        except:
            pass
        
        update_speed_stats(response_time)
        return response_time
    except Exception as e:
        print(f"⚠️ خطأ في قياس سرعة الاستجابة: {e}")
        return 0.15

def update_speed_stats(response_time):
    """تحديث إحصائيات سرعة الاستجابة"""
    response_speed_info['response_times'].append(response_time)
    
    if len(response_speed_info['response_times']) > 100:
        response_speed_info['response_times'] = response_speed_info['response_times'][-100:]
    
    response_speed_info['last_10_responses'].append(response_time)
    if len(response_speed_info['last_10_responses']) > 10:
        response_speed_info['last_10_responses'] = response_speed_info['last_10_responses'][-10:]
    
    if response_speed_info['response_times']:
        avg_time = statistics.mean(response_speed_info['response_times'][-10:])
    else:
        avg_time = response_time
    
    response_speed_info['avg_response_time'] = avg_time
    response_speed_info['last_check'] = datetime.now()
    
    response_speed_info['min_response'] = min(response_speed_info.get('min_response', float('inf')), response_time)
    response_speed_info['max_response'] = max(response_speed_info.get('max_response', 0), response_time)
    
    if avg_time <= 0.05:
        speed_category = "M0.05 ⚡⚡⚡"
    elif avg_time <= 0.1:
        speed_category = "M0.10 ⚡⚡"
    elif avg_time <= 0.15:
        speed_category = "M0.15 ⚡"
    elif avg_time <= 0.2:
        speed_category = "M0.20 🐇"
    elif avg_time <= 0.3:
        speed_category = "M0.30 🚶"
    elif avg_time <= 0.5:
        speed_category = "M0.50 🐢"
    elif avg_time <= 1.0:
        speed_category = "M1.00 🐌"
    else:
        speed_category = f"M{avg_time:.2f} ⚠️"
    
    response_speed_info['speed_category'] = speed_category
    return avg_time

def get_response_speed():
    """الحصول على معلومات سرعة الاستجابة"""
    response_time = measure_response_speed()
    return response_speed_info

# ========== دوال التحقق ==========

def check_for_malicious_code(file_path):
    """فحص الملف لأكواد ضارة"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        dangerous_patterns = [
            r"os\.system\(", r"subprocess\.", r"eval\(", r"exec\(", r"open\(",
            r"import\s+os", r"import\s+subprocess", r"__import__\(", r"pickle\.",
            r"requests\.", r"urllib\.", r"socket\.", r"shutil\.", r"sys\.exit\("
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content):
                print(f"⚠️ تم اكتشاف نمط خطير في الملف: {pattern}")
                return True
        
        # تحليل الكود باستخدام ast
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'open', 'system']:
                            print(f"⚠️ تم اكتشاف دالة خطيرة: {node.func.id}")
                            return True
        except Exception as e:
            print(f"⚠️ خطأ في تحليل الكود: {e}")
            return True
        
        return False
    except Exception as e:
        print(f"⚠️ خطأ في قراءة الملف: {e}")
        return True

def check_for_viruses(file_path):
    """فحص الملف للفيروسات"""
    if CLAMAV_AVAILABLE and cd:
        try:
            scan_result = cd.scan_file(file_path)
            if scan_result:
                print(f"⚠️ تم اكتشاف فيروس في الملف: {scan_result}")
                return True
            return False
        except Exception as e:
            print(f"⚠️ خطأ في فحص الفيروسات: {e}")
            return False
    else:
        print("ℹ️ ClamAV غير متوفر، سيتم فحص الكود الضار فقط")
        return False

# ========== تهيئة البوت ==========

bot = telebot.TeleBot(BOT_TOKEN)

# ========== Middleware ==========

@bot.middleware_handler(update_types=['message'])
def middleware(bot_instance, message):
    """ميدل وير للتحقق من الحظر والتحديثات"""
    if message.from_user:
        user_id = message.from_user.id
        
        # التحقق إذا كان المستخدم محظور
        if is_user_banned(user_id):
            bot.send_message(user_id, "❌ أنت محظور من استخدام البوت!")
            return
        
        # تحديث إحصائيات المستخدم
        update_user_stats(
            user_id,
            message.from_user.username or "",
            message.from_user.first_name or "",
            message.from_user.last_name or ""
        )
        
        # قياس سرعة الاستجابة
        start_time = time.time()
        yield
        end_time = time.time()
        response_time = end_time - start_time
        update_speed_stats(response_time)

# ========== الأوامر العامة ==========

@bot.message_handler(commands=['start'])
def start(message):
    if is_user_banned(message.from_user.id):
        return
    
    user_name = message.from_user.first_name
    speed_info = get_response_speed()
    
    last_check = speed_info['last_check']
    if last_check:
        time_diff = datetime.now() - last_check
        if time_diff.total_seconds() < 60:
            last_check_str = f"منذ {int(time_diff.total_seconds())} ثانية"
        elif time_diff.total_seconds() < 3600:
            last_check_str = f"منذ {int(time_diff.total_seconds()/60)} دقيقة"
        else:
            last_check_str = last_check.strftime("%H:%M:%S")
    else:
        last_check_str = "لم يتم القياس بعد"
    
    welcome_message = (
        "👋🏻 مرحباً بك، {user_name}!\n\n"
        "أنا بوت متعدد الاستخدامات يساعدك في:\n"
        "📤 رفع الملفات بسهولة.\n"
        "⚡ تشغيل الملفات بأمان.\n\n"
        "📊 **معلومات سرعة البوت:**\n"
        "⚡ **سرعة الاستجابة:** {speed}\n"
        "⏱️ **متوسط الوقت:** {avg:.3f} ثانية\n"
        "📈 **أسرع استجابة:** {min:.3f} ثانية\n"
        "📉 **أبطأ استجابة:** {max:.3f} ثانية\n"
        "🔢 **عدد القياسات:** {count}\n"
        "🕐 **آخر تحديث:** {last_check}\n\n"
        "استخدم الأزرار أدناه للتفاعل مع البوت."
    ).format(
        user_name=user_name,
        speed=speed_info['speed_category'],
        avg=speed_info['avg_response_time'],
        min=speed_info['min_response'],
        max=speed_info['max_response'],
        count=len(speed_info['response_times']),
        last_check=last_check_str
    )
    
    keyboard = create_main_keyboard(message.from_user.id)
    image_url = 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTc_tNTW84d2jsH0ecXzDQRoIWMtNGzv734Kw&usqp=CAU'
    bot.send_photo(message.chat.id, image_url, caption=welcome_message, 
                   reply_markup=keyboard, parse_mode='Markdown')

@bot.message_handler(commands=['admin'])
def admin_panel(message):
    """لوحة تحكم الأدمن"""
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, "❌ ليس لديك صلاحية الوصول إلى لوحة الأدمن!")
        return
    
    admin_text = "🛠️ **لوحة تحكم الأدمن**\n\n"
    admin_text += "👑 **الأدمن الرئيسي:**\n"
    admin_text += f"• المالك: {OWNER_ID}\n\n"
    
    # إحصائيات البوت
    stats = get_bot_statistics()
    admin_text += "📊 **إحصائيات البوت:**\n"
    admin_text += f"• إجمالي المستخدمين: {stats['total_users']}\n"
    admin_text += f"• النشطين اليوم: {stats['active_today']}\n"
    admin_text += f"• النشطين الأسبوع: {stats['active_week']}\n"
    admin_text += f"• الملفات المرفوعة: {stats['total_files']}\n"
    admin_text += f"• المحظورين: {stats['banned_users']}\n"
    admin_text += f"• الأدمن المساعدين: {stats['assistant_admins']}\n\n"
    
    # معلومات الفحص
    admin_text += "🛡️ **نظام الفحص:**\n"
    if CLAMAV_AVAILABLE:
        admin_text += "• فحص الفيروسات: ✅ متاح\n"
    else:
        admin_text += "• فحص الفيروسات: ❌ غير متاح\n"
    admin_text += "• فحص الأكواد الضارة: ✅ نشط\n\n"
    
    bot.send_message(message.chat.id, admin_text, 
                     reply_markup=create_admin_keyboard(), parse_mode='Markdown')

@bot.message_handler(commands=['speed'])
def speed_command(message):
    """فحص سرعة البوت"""
    bot.send_message(message.chat.id, "⚡ جاري قياس سرعة استجابة البوت...")
    response_time = measure_response_speed()
    speed_info = get_response_speed()
    
    speed_message = (
        "📊 **نتيجة قياس سرعة الاستجابة:**\n\n"
        "⚡ **سرعة البوت:** {speed}\n"
        "⏱️ **الاستجابة الأخيرة:** {last:.3f} ثانية\n"
        "📊 **متوسط السرعة:** {avg:.3f} ثانية\n"
        "📈 **أسرع استجابة:** {min:.3f} ثانية\n"
        "📉 **أبطأ استجابة:** {max:.3f} ثانية\n"
        "🔢 **إجمالي القياسات:** {count}"
    ).format(
        speed=speed_info['speed_category'],
        last=response_time,
        avg=speed_info['avg_response_time'],
        min=speed_info['min_response'],
        max=speed_info['max_response'],
        count=len(speed_info['response_times'])
    )
    
    bot.send_message(message.chat.id, speed_message, parse_mode='Markdown')

@bot.message_handler(commands=['help'])
def help_command(message):
    """عرض مساعدة"""
    help_text = (
        "📚 **قائمة الأوامر المتاحة:**\n\n"
        "• /start - بدء استخدام البوت\n"
        "• /speed - فحص سرعة البوت\n"
        "• /ping - اختبار سرعة الاستجابة\n"
        "• /help - عرض هذه الرسالة\n"
    )
    
    if is_admin(message.from_user.id):
        help_text += "\n👑 **أوامر الأدمن:**\n"
        help_text += "• /admin - لوحة تحكم الأدمن\n"
    
    bot.send_message(message.chat.id, help_text, parse_mode='Markdown')

@bot.message_handler(commands=['ping'])
def ping_command(message):
    """اختبار Ping"""
    start_time = time.time()
    msg = bot.send_message(message.chat.id, "🏓 Pong...")
    end_time = time.time()
    
    response_time = (end_time - start_time) * 1000  # ملي ثانية
    
    bot.edit_message_text(
        f"🏓 **Pong!**\n\n"
        f"⏱️ **سرعة الاستجابة:** {response_time:.0f}ms\n"
        f"⚡ **سرعة البوت:** {response_speed_info['speed_category']}",
        message.chat.id,
        msg.message_id,
        parse_mode='Markdown'
    )

# ========== لوحات المفاتيح ==========

def create_main_keyboard(user_id):
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("رفع ملف 📤", callback_data='upload'))
    keyboard.add(types.InlineKeyboardButton("عرض جميع الملفات 📂", callback_data='show_files'))
    keyboard.add(types.InlineKeyboardButton("فحص سرعة البوت ⚡", callback_data='check_speed'))
    
    if is_admin(user_id):
        keyboard.add(types.InlineKeyboardButton("🛠️ لوحة الأدمن", callback_data='admin_panel'))
    
    return keyboard

def create_admin_keyboard():
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    
    keyboard.add(
        types.InlineKeyboardButton("📊 الإحصائيات", callback_data='admin_stats'),
        types.InlineKeyboardButton("📢 القنوات الإجبارية", callback_data='admin_channels')
    )
    
    keyboard.add(
        types.InlineKeyboardButton("👤 حظر مستخدم", callback_data='admin_ban'),
        types.InlineKeyboardButton("✅ فك حظر مستخدم", callback_data='admin_unban')
    )
    
    keyboard.add(
        types.InlineKeyboardButton("🛡️ إضافة أدمن مساعد", callback_data='admin_add_assistant'),
        types.InlineKeyboardButton("❌ إزالة أدمن مساعد", callback_data='admin_remove_assistant')
    )
    
    keyboard.add(
        types.InlineKeyboardButton("📋 عرض المحظورين", callback_data='admin_show_banned'),
        types.InlineKeyboardButton("👥 عرض الأدمن المساعدين", callback_data='admin_show_assistants')
    )
    
    keyboard.add(
        types.InlineKeyboardButton("🔙 القائمة الرئيسية", callback_data='back_to_main')
    )
    
    return keyboard

# ========== معالجة الكالي باك ==========

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    user_id = call.from_user.id
    
    # التحقق من صلاحيات الأدمن
    if call.data.startswith('admin_') and not is_admin(user_id):
        bot.answer_callback_query(call.id, "❌ ليس لديك صلاحية الأدمن!")
        return
    
    if call.data == 'upload':
        bot.send_message(call.message.chat.id, "📤 يرجى إرسال ملف بايثون لي تشغيله.")
        bot.register_next_step_handler(call.message, handle_document)
    
    elif call.data == 'show_files':
        show_all_files(call.message.chat.id, user_id)
    
    elif call.data == 'check_speed':
        speed_command(call.message)
    
    elif call.data == 'admin_panel':
        admin_panel(call.message)
    
    elif call.data == 'admin_stats':
        show_admin_stats(call)
    
    elif call.data == 'admin_channels':
        show_channels_menu(call)
    
    elif call.data == 'admin_ban':
        bot.send_message(call.message.chat.id, "👤 أرسل معرف المستخدم (ID) أو الرد على رسالته للحظر:")
        bot.register_next_step_handler(call.message, process_ban_user)
    
    elif call.data == 'admin_unban':
        bot.send_message(call.message.chat.id, "✅ أرسل معرف المستخدم (ID) لفك الحظر:")
        bot.register_next_step_handler(call.message, process_unban_user)
    
    elif call.data == 'admin_add_assistant':
        bot.send_message(call.message.chat.id, "🛡️ أرسل معرف المستخدم (ID) لإضافته كأدمن مساعد:")
        bot.register_next_step_handler(call.message, process_add_assistant)
    
    elif call.data == 'admin_remove_assistant':
        bot.send_message(call.message.chat.id, "❌ أرسل معرف المستخدم (ID) لإزالة صلاحية الأدمن:")
        bot.register_next_step_handler(call.message, process_remove_assistant)
    
    elif call.data == 'admin_show_banned':
        show_banned_users(call)
    
    elif call.data == 'admin_show_assistants':
        show_assistant_admins(call)
    
    elif call.data == 'back_to_main':
        bot.delete_message(call.message.chat.id, call.message.message_id)
        start(call.message)
    
    elif call.data == 'add_channel':
        bot.send_message(call.message.chat.id, "📢 أرسل معرف القناة أو اليوزرنيم (مثال: @channel_username):")
        bot.register_next_step_handler(call.message, process_add_channel)
    
    elif call.data == 'remove_channel':
        show_channels_for_removal(call)
    
    elif call.data == 'view_channels':
        show_required_channels(call)
    
    elif call.data.startswith('delete_channel_'):
        channel_id = call.data.split('delete_channel_')[1]
        remove_required_channel(channel_id)
        bot.answer_callback_query(call.id, "✅ تم حذف القناة بنجاح!")
        show_channels_menu(call)
    
    elif call.data.startswith('run_'):
        file_name = call.data.split('run_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(user_id), file_name)
        if os.path.exists(file_path):
            # فحص الملف قبل التشغيل
            if check_for_malicious_code(file_path):
                bot.send_message(call.message.chat.id, "❌ الملف يحتوي على أكواد ضارة! تم إيقاف التشغيل.")
                return
            
            bot.send_message(call.message.chat.id, f"🚀 تم تشغيل الملف: {file_name}")
            start_file_thread(file_path, call.message.chat.id)
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    
    elif call.data.startswith('stop_'):
        file_name = call.data.split('stop_')[1]
        chat_id = call.message.chat.id
        if chat_id in running_processes:
            process = running_processes[chat_id]
            process.terminate()
            del running_processes[chat_id]
            bot.send_message(chat_id, f"⚠️ تم إيقاف الملف: {file_name}")
        else:
            bot.send_message(chat_id, "❗ لا يوجد ملف قيد التشغيل.")
    
    elif call.data.startswith('delete_'):
        file_name = call.data.split('delete_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(user_id), file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.send_message(call.message.chat.id, f"🗑️ تم حذف الملف: {file_name}")
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    
    elif call.data.startswith('restart_'):
        file_name = call.data.split('restart_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(user_id), file_name)
        if os.path.exists(file_path):
            # فحص الملف قبل التشغيل
            if check_for_malicious_code(file_path):
                bot.send_message(call.message.chat.id, "❌ الملف يحتوي على أكواد ضارة! تم إيقاف التشغيل.")
                return
            
            bot.send_message(call.message.chat.id, f"🔄 تم إعادة تشغيل الملف: {file_name}")
            start_file_thread(file_path, call.message.chat.id)
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    
    elif call.data.startswith('approve_'):
        file_name = call.data.split('approve_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(user_id), file_name)
        if os.path.exists(file_path):
            # فحص الملف قبل التشغيل
            if check_for_malicious_code(file_path):
                bot.send_message(call.message.chat.id, "❌ الملف يحتوي على أكواد ضارة! تم رفض التشغيل.")
                return
            
            bot.send_message(call.message.chat.id, f"✅ تمت الموافقة على تشغيل الملف: {file_name}")
            start_file_thread(file_path, call.message.chat.id)
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    
    elif call.data.startswith('reject_'):
        file_name = call.data.split('reject_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(user_id), file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.send_message(call.message.chat.id, f"❌ تم رفض الملف: {file_name} وحذفه.")
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")

# ========== دوال الأدمن ==========

def show_admin_stats(call):
    """عرض إحصائيات البوت للأدمن"""
    stats = get_bot_statistics()
    speed_info = get_response_speed()
    
    stats_message = (
        "📊 **إحصائيات البوت التفصيلية**\n\n"
        "👥 **المستخدمين:**\n"
        f"• الإجمالي: {stats['total_users']} مستخدم\n"
        f"• النشطين اليوم: {stats['active_today']}\n"
        f"• النشطين هذا الأسبوع: {stats['active_week']}\n\n"
        
        "📁 **الملفات:**\n"
        f"• الملفات المرفوعة: {stats['total_files']}\n\n"
        
        "🛡️ **الإدارة:**\n"
        f"• المستخدمين المحظورين: {stats['banned_users']}\n"
        f"• الأدمن المساعدين: {stats['assistant_admins']}\n\n"
        
        "⚡ **أداء البوت:**\n"
        f"• سرعة الاستجابة: {speed_info['speed_category']}\n"
        f"• متوسط الوقت: {speed_info['avg_response_time']:.3f} ثانية\n"
        f"• عدد القياسات: {len(speed_info['response_times'])}\n\n"
        
        "🛡️ **نظام الفحص:**\n"
        f"• فحص الفيروسات: {'✅' if CLAMAV_AVAILABLE else '❌'}\n"
        f"• فحص الأكواد الضارة: ✅\n\n"
        
        "📈 **آخر تحديث:** {time}"
    ).format(
        time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔄 تحديث", callback_data='admin_stats'))
    keyboard.add(types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_panel'))
    
    bot.edit_message_text(stats_message, call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard, parse_mode='Markdown')

def show_channels_menu(call):
    """عرض قائمة إدارة القنوات"""
    channels = get_required_channels()
    
    channels_text = "📢 **إدارة القنوات الإجبارية**\n\n"
    
    if channels:
        channels_text += f"📊 **عدد القنوات:** {len(channels)}\n\n"
        channels_text += "**القنوات الحالية:**\n"
        
        for idx, channel in enumerate(channels[:5], 1):
            channels_text += f"{idx}. {channel[3]} (@{channel[2]})\n"
        
        if len(channels) > 5:
            channels_text += f"\n... و {len(channels) - 5} قنوات أخرى"
    else:
        channels_text += "❌ لا توجد قنوات إجبارية مضافة.\n"
    
    keyboard = types.InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        types.InlineKeyboardButton("➕ إضافة قناة", callback_data='add_channel'),
        types.InlineKeyboardButton("🗑️ حذف قناة", callback_data='remove_channel')
    )
    keyboard.add(
        types.InlineKeyboardButton("👁️ عرض القنوات", callback_data='view_channels'),
        types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_panel')
    )
    
    bot.edit_message_text(channels_text, call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard, parse_mode='Markdown')

def process_add_channel(message):
    """معالجة إضافة قناة جديدة"""
    try:
        channel_input = message.text.strip()
        
        # إزالة @ إذا موجود
        if channel_input.startswith('@'):
            channel_username = channel_input[1:]
        else:
            channel_username = channel_input
        
        # محاولة الحصول على معلومات القناة
        try:
            chat = bot.get_chat(f"@{channel_username}")
            channel_id = str(chat.id)
            channel_name = chat.title
            
            if add_required_channel(channel_id, channel_username, channel_name, message.from_user.id):
                bot.send_message(message.chat.id, 
                               f"✅ تمت إضافة القناة بنجاح!\n\n"
                               f"📢 **اسم القناة:** {channel_name}\n"
                               f"👤 **اليوزرنيم:** @{channel_username}\n"
                               f"🆔 **المعرف:** {channel_id}")
            else:
                bot.send_message(message.chat.id, "❌ فشل في إضافة القناة!")
        
        except Exception as e:
            bot.send_message(message.chat.id, f"❌ لم أتمكن من العثور على القناة!\n\nالخطأ: {str(e)}")
    
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {str(e)}")

def show_channels_for_removal(call):
    """عرض القنوات للإزالة"""
    channels = get_required_channels()
    
    if not channels:
        bot.answer_callback_query(call.id, "❌ لا توجد قنوات لحذفها!")
        return
    
    keyboard = types.InlineKeyboardMarkup()
    
    for channel in channels[:5]:  # عرض أول 5 قنوات فقط
        channel_id = channel[1]
        channel_name = channel[3]
        keyboard.add(
            types.InlineKeyboardButton(
                f"🗑️ {channel_name[:20]}...",
                callback_data=f'delete_channel_{channel_id}'
            )
        )
    
    keyboard.add(types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_channels'))
    
    bot.edit_message_text("🗑️ **اختر القناة التي تريد حذفها:**",
                         call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard)

def show_required_channels(call):
    """عرض جميع القنوات الإجبارية"""
    channels = get_required_channels()
    
    channels_text = "📢 **القنوات الإجبارية**\n\n"
    
    if channels:
        for idx, channel in enumerate(channels, 1):
            if len(channel) > 5:
                try:
                    added_date = datetime.strptime(channel[5], "%Y-%m-%d %H:%M:%S")
                    date_str = added_date.strftime("%Y-%m-%d")
                except:
                    date_str = "غير معروف"
            else:
                date_str = "غير معروف"
                
            channels_text += (
                f"**{idx}. {channel[3]}**\n"
                f"👤 @{channel[2]}\n"
                f"🆔 {channel[1]}\n"
                f"📅 {date_str}\n"
                f"━━━━━━━━━━━━━━\n"
            )
    else:
        channels_text += "❌ لا توجد قنوات إجبارية.\n"
    
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_channels'))
    
    bot.edit_message_text(channels_text, call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard, parse_mode='Markdown')

def process_ban_user(message):
    """معالجة حظر مستخدم"""
    try:
        if message.reply_to_message:
            user_id = message.reply_to_message.from_user.id
            username = message.reply_to_message.from_user.username or ""
            first_name = message.reply_to_message.from_user.first_name or ""
            last_name = message.reply_to_message.from_user.last_name or ""
        else:
            user_id = int(message.text.strip())
            # محاولة الحصول على معلومات المستخدم
            try:
                user = bot.get_chat(user_id)
                username = user.username or ""
                first_name = user.first_name or ""
                last_name = user.last_name or ""
            except:
                username = ""
                first_name = ""
                last_name = ""
        
        reason = "بدون سبب"  # يمكن إضافة حقل للسبب
        
        if ban_user(user_id, username, first_name, last_name, message.from_user.id, reason):
            bot.send_message(message.chat.id, 
                           f"✅ تم حظر المستخدم بنجاح!\n\n"
                           f"👤 **المستخدم:** {first_name} {last_name}\n"
                           f"🆔 **المعرف:** {user_id}\n"
                           f"👤 **اليوزرنيم:** @{username if username else 'لا يوجد'}\n"
                           f"📝 **السبب:** {reason}")
        else:
            bot.send_message(message.chat.id, "❌ فشل في حظر المستخدم!")
    
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {str(e)}\n\nتأكد من إرسال معرف صحيح أو الرد على رسالة المستخدم.")

def process_unban_user(message):
    """معالجة فك حظر مستخدم"""
    try:
        user_id = int(message.text.strip())
        
        if unban_user(user_id):
            bot.send_message(message.chat.id, f"✅ تم فك حظر المستخدم {user_id} بنجاح!")
        else:
            bot.send_message(message.chat.id, "❌ فشل في فك الحظر أو المستخدم غير محظور!")
    
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {str(e)}\n\nتأكد من إرسال معرف صحيح.")

def process_add_assistant(message):
    """معالجة إضافة أدمن مساعد"""
    try:
        user_id = int(message.text.strip())
        
        # محاولة الحصول على معلومات المستخدم
        try:
            user = bot.get_chat(user_id)
            username = user.username or ""
            first_name = user.first_name or ""
            last_name = user.last_name or ""
        except:
            bot.send_message(message.chat.id, "❌ لم أتمكن من العثور على المستخدم!")
            return
        
        if add_assistant_admin(user_id, username, first_name, last_name, message.from_user.id):
            bot.send_message(message.chat.id,
                           f"✅ تمت إضافة الأدمن المساعد بنجاح!\n\n"
                           f"👤 **الاسم:** {first_name} {last_name}\n"
                           f"🆔 **المعرف:** {user_id}\n"
                           f"👤 **اليوزرنيم:** @{username if username else 'لا يوجد'}")
        else:
            bot.send_message(message.chat.id, "❌ فشل في إضافة الأدمن المساعد!")
    
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {str(e)}")

def process_remove_assistant(message):
    """معالجة إزالة أدمن مساعد"""
    try:
        user_id = int(message.text.strip())
        
        if remove_assistant_admin(user_id):
            bot.send_message(message.chat.id, f"✅ تمت إزالة الأدمن المساعد {user_id} بنجاح!")
        else:
            bot.send_message(message.chat.id, "❌ فشل في الإزالة أو المستخدم ليس أدمن مساعد!")
    
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {str(e)}")

def show_banned_users(call):
    """عرض المستخدمين المحظورين"""
    users = get_banned_users()
    
    banned_text = "🚫 **المستخدمين المحظورين**\n\n"
    
    if users:
        banned_text += f"📊 **عدد المحظورين:** {len(users)}\n\n"
        
        for idx, user in enumerate(users[:5], 1):  # عرض أول 5 مستخدمين فقط
            if len(user) > 5:
                try:
                    ban_date = datetime.strptime(user[5], "%Y-%m-%d %H:%M:%S")
                    date_str = ban_date.strftime("%Y-%m-%d")
                except:
                    date_str = "غير معروف"
            else:
                date_str = "غير معروف"
                
            reason = user[6] if len(user) > 6 else 'بدون سبب'
            banned_text += (
                f"**{idx}. {user[2]} {user[3]}**\n"
                f"🆔 {user[0]}\n"
                f"👤 @{user[1] if user[1] else 'لا يوجد'}\n"
                f"📅 {date_str}\n"
                f"📝 السبب: {reason}\n"
                f"━━━━━━━━━━━━━━\n"
            )
        
        if len(users) > 5:
            banned_text += f"\n... و {len(users) - 5} مستخدم آخر"
    else:
        banned_text += "✅ لا يوجد مستخدمين محظورين.\n"
    
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔄 تحديث", callback_data='admin_show_banned'))
    keyboard.add(types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_panel'))
    
    bot.edit_message_text(banned_text, call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard, parse_mode='Markdown')

def show_assistant_admins(call):
    """عرض الأدمن المساعدين"""
    admins = get_assistant_admins()
    
    admins_text = "🛡️ **الأدمن المساعدين**\n\n"
    
    if admins:
        admins_text += f"📊 **عدد المساعدين:** {len(admins)}\n\n"
        
        for idx, admin in enumerate(admins, 1):
            if len(admin) > 5:
                try:
                    added_date = datetime.strptime(admin[5], "%Y-%m-%d %H:%M:%S")
                    date_str = added_date.strftime("%Y-%m-%d")
                except:
                    date_str = "غير معروف"
            else:
                date_str = "غير معروف"
                
            admins_text += (
                f"**{idx}. {admin[2]} {admin[3]}**\n"
                f"🆔 {admin[0]}\n"
                f"👤 @{admin[1] if admin[1] else 'لا يوجد'}\n"
                f"📅 {date_str}\n"
                f"━━━━━━━━━━━━━━\n"
            )
    else:
        admins_text += "❌ لا يوجد أدمن مساعدين.\n"
    
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("🔄 تحديث", callback_data='admin_show_assistants'))
    keyboard.add(types.InlineKeyboardButton("🔙 رجوع", callback_data='admin_panel'))
    
    bot.edit_message_text(admins_text, call.message.chat.id, call.message.message_id,
                         reply_markup=keyboard, parse_mode='Markdown')

# ========== دوال الملفات ==========

def show_all_files(chat_id, user_id):
    user_folder = os.path.join(UPLOAD_FOLDER, str(user_id))
    if os.path.exists(user_folder):
        files = os.listdir(user_folder)
        if files:
            for file_name in files:
                show_file_buttons(chat_id, file_name)
        else:
            bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")
    else:
        bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")

def show_file_buttons(chat_id, file_name):
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(
        types.InlineKeyboardButton(f"تشغيل 🚀 {file_name}", callback_data=f'run_{file_name}'),
        types.InlineKeyboardButton(f"إيقاف ⏹️ {file_name}", callback_data=f'stop_{file_name}')
    )
    keyboard.add(
        types.InlineKeyboardButton(f"حذف 🗑️ {file_name}", callback_data=f'delete_{file_name}'),
        types.InlineKeyboardButton(f"إعادة تشغيل 🔄 {file_name}", callback_data=f'restart_{file_name}')
    )
    bot.send_message(chat_id, f"📁 الملف: {file_name}", reply_markup=keyboard)

@bot.message_handler(content_types=['document'])
def handle_document(message):
    if is_user_banned(message.from_user.id):
        return
    
    user_id = message.from_user.id
    user_name = message.from_user.username or ""
    full_name = message.from_user.first_name + " " + (message.from_user.last_name or "")
    
    if message.document:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        user_folder = os.path.join(UPLOAD_FOLDER, str(user_id))  
        if not os.path.exists(user_folder):  
            os.makedirs(user_folder)  

        file_path = os.path.join(user_folder, message.document.file_name)  
        with open(file_path, 'wb') as new_file:  
            new_file.write(downloaded_file)  

        if user_id not in user_files:  
            user_files[user_id] = []  
        user_files[user_id].append(message.document.file_name)

        # فحص الملف
        bot.send_message(message.chat.id, "🔍 جاري فحص الملف...")
        
        has_malicious = check_for_malicious_code(file_path)
        has_virus = check_for_viruses(file_path)
        
        if has_malicious or has_virus:
            bot.send_message(message.chat.id, "⚠️ تم رفض الملف! يحتوي على أكواد ضارة أو فيروسات.")
            os.remove(file_path)
            return
        
        bot.send_message(message.chat.id, "✅ تم رفع الملف بنجاح وفحصه!")

        keyboard = types.InlineKeyboardMarkup()
        keyboard.add(types.InlineKeyboardButton("موافقة ✅", callback_data=f'approve_{message.document.file_name}'))
        keyboard.add(types.InlineKeyboardButton("رفض ❌", callback_data=f'reject_{message.document.file_name}'))
        
        # إرسال للمالك
        try:
            with open(file_path, 'rb') as f:
                bot.send_document(OWNER_ID, f, 
                                 caption=f"📤 تم رفع ملف جديد من:\n👤 الاسم: {full_name}\n🆔 المعرف: {user_id}\n📱 @{user_name}\n📁 الملف: {message.document.file_name}\n\nمطور البوت: Sifo (@S_sifo)", 
                                 reply_markup=keyboard)
        except Exception as e:
            print(f"خطأ في إرسال الملف للمالك: {e}")

        bot.send_message(message.chat.id, "📤 تم إرسال الملف إلى المالك للتحقق. يرجى الانتظار...")

def start_file_thread(file_path, chat_id):
    thread = threading.Thread(target=run_file, args=(file_path, chat_id))
    thread.start()

def run_file(file_path, chat_id):
    try:
        process = subprocess.Popen(['python', file_path])
        running_processes[chat_id] = process
        bot.send_message(chat_id, "🚀 الملف قيد التشغيل.")
        
        monitor_process(process, chat_id, file_path)
    except Exception as e:  
        bot.send_message(chat_id, f"⚠️ حدث خطأ أثناء تشغيل الملف: {e}")

def monitor_process(process, chat_id, file_path):
    while True:
        time.sleep(10)
        if process.poll() is not None:
            bot.send_message(chat_id, f"⚠️ الملف {os.path.basename(file_path)} توقف. جاري إعادة التشغيل...")
            run_file(file_path, chat_id)
            break

# ========== التشغيل ==========

def periodic_response_check():
    """فحص دوري لسرعة الاستجابة"""
    while True:
        time.sleep(300)  # كل 5 دقائق
        try:
            measure_response_speed()
            print(f"✅ تم تحديث سرعة الاستجابة: {response_speed_info['speed_category']}")
        except Exception as e:
            print(f"⚠️ خطأ في الفحص الدوري للسرعة: {e}")

response_check_thread = threading.Thread(target=periodic_response_check)
response_check_thread.daemon = True
response_check_thread.start()

def run_bot():
    print("🚀 بدء تشغيل البوت...")
    print(f"👑 المالك: {OWNER_ID}")
    print(f"🛡️ عدد الأدمن: {len(ADMINS)}")
    print(f"💾 قاعدة البيانات: {DB_FILE}")
    print(f"📁 مجلد الملفات: {UPLOAD_FOLDER}")
    
    if CLAMAV_AVAILABLE:
        print("✅ ClamAV: متاح للفحص")
    else:
        print("⚠️ ClamAV: غير متاح (فحص الكود الضار فقط)")
    
    while True:
        try:
            measure_response_speed()
            print(f"⚡ سرعة البوت: {response_speed_info['speed_category']}")
            
            bot.polling(none_stop=True, interval=0, timeout=20)
        except Exception as e:
            print(f"⚠️ حدث خطأ: {e}. إعادة المحاولة خلال 10 ثوانٍ...")
            time.sleep(10)

if __name__ == "__main__":
    run_bot()