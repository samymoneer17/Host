import telebot
from telebot import types
import os
import time
import subprocess
import threading
import random
import psutil
import ast
import pyclamd
import re
import datetime
import statistics  # لإحصائيات السرعة

# تعيين توكن البوت كمتغير
BOT_TOKEN = '8156912979:AAHyLYBEM7GBOfFjvwFtJ9Cxkg4uEqxUFLY'

# اسم القناة
CHANNEL_USERNAME = '@pythonyemen1'

# معرف المالك
OWNER_ID = 7627857345

# مسار حفظ الملفات
UPLOAD_FOLDER = 'uploaded_files'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# لتخزين الملفات لكل مستخدم
user_files = {}

# لتخزين العمليات الجارية
running_processes = {}

# لتخزين معلومات سرعة الاستجابة
response_speed_info = {
    'last_check': None,
    'response_times': [],  # قائمة بأوقات الاستجابة الأخيرة
    'avg_response_time': 0.15,  # القيمة الافتراضية بالثواني
    'speed_category': 'M0.15',  # القيمة الافتراضية
    'min_response': float('inf'),
    'max_response': 0,
    'last_10_responses': []  # آخر 10 قياسات للاستجابة
}

# تهيئة ClamAV للتحقق من الفيروسات
try:
    cd = pyclamd.ClamdAgnostic()
    cd.ping()  # التحقق من اتصال ClamAV
except Exception as e:
    print(f"⚠️ خطأ في تهيئة ClamAV: {e}")
    cd = None

# دالة لقياس سرعة استجابة البوت
def measure_response_speed():
    """قياس سرعة استجابة البوت عن طريق إرسال رسالة وقياس وقت الرد"""
    try:
        start_time = time.time()
        
        # إنشاء معرف فريد للاختبار
        test_id = f"speed_test_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # إرسال رسالة اختبار
        test_message = bot.send_message(OWNER_ID, f"⏱️ اختبار السرعة - {test_id}")
        
        end_time = time.time()
        response_time = end_time - start_time
        
        # حذف رسالة الاختبار
        try:
            bot.delete_message(OWNER_ID, test_message.message_id)
        except:
            pass
        
        # تحديث إحصائيات السرعة
        update_speed_stats(response_time)
        
        return response_time
    except Exception as e:
        print(f"⚠️ خطأ في قياس سرعة الاستجابة: {e}")
        return 0.15  # قيمة افتراضية في حالة الخطأ

def update_speed_stats(response_time):
    """تحديث إحصائيات سرعة الاستجابة"""
    # إضافة الوقت الحالي للقائمة
    response_speed_info['response_times'].append(response_time)
    
    # حفظ آخر 100 قياس فقط
    if len(response_speed_info['response_times']) > 100:
        response_speed_info['response_times'] = response_speed_info['response_times'][-100:]
    
    # تحديث آخر 10 قياسات
    response_speed_info['last_10_responses'].append(response_time)
    if len(response_speed_info['last_10_responses']) > 10:
        response_speed_info['last_10_responses'] = response_speed_info['last_10_responses'][-10:]
    
    # حساب المتوسط
    if response_speed_info['response_times']:
        avg_time = statistics.mean(response_speed_info['response_times'][-10:])  # متوسط آخر 10 قياسات
    else:
        avg_time = response_time
    
    # تحديث القيم
    response_speed_info['avg_response_time'] = avg_time
    response_speed_info['last_check'] = datetime.datetime.now()
    
    # تحديث القيم القصوى والدنيا
    response_speed_info['min_response'] = min(response_speed_info.get('min_response', float('inf')), response_time)
    response_speed_info['max_response'] = max(response_speed_info.get('max_response', 0), response_time)
    
    # تحديد فئة السرعة بناءً على وقت الاستجابة
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
    """الحصول على معلومات سرعة الاستجابة مع إجراء فحص جديد"""
    # إجراء فحص سرعة جديد
    response_time = measure_response_speed()
    
    return response_speed_info

# دالة للتحقق من وجود أكواد ضارة في الملف
def check_for_malicious_code(file_path):
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
                return True
        
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'open', 'system']:
                            return True
        except Exception as e:
            print(f"⚠️ خطأ في تحليل الكود: {e}")
            return True
        
        return False
    except Exception as e:
        print(f"⚠️ خطأ في قراءة الملف: {e}")
        return True

def check_for_viruses(file_path):
    if cd:
        try:
            scan_result = cd.scan_file(file_path)
            if scan_result:
                print(f"⚠️ تم اكتشاف فيروس في الملف: {scan_result}")
                return True
            return False
        except Exception as e:
            print(f"⚠️ خطأ في فحص الملف: {e}")
            return True
    else:
        print("⚠️ ClamAV غير متوفر.")
        return False

def show_animated_message(chat_id, file_name):
    emojis = ["👀", "👋🏻", "🤝🏻", "🎉", "❤️", "😜", "😇", "😭", "😅", "😱", "🤐", "🤯", "🤒", "🤡", "👻", "😷", "🥴"]
    message = bot.send_message(chat_id, f"جاري فحص الملف {file_name}... {emojis[0]}")
    
    for i in range(1, 10):
        time.sleep(1)
        bot.edit_message_text(f"جاري فحص الملف {file_name}... {emojis[i % len(emojis)]}", chat_id, message.message_id)
    
    bot.delete_message(chat_id, message.message_id)

bot = telebot.TeleBot(BOT_TOKEN)

# قياس سرعة استجابة البوت لكل رسالة
@bot.middleware_handler(update_types=['message'])
def measure_speed_middleware(bot_instance, message):
    """ميدل وير لقياس سرعة استجابة البوت لكل رسالة"""
    start_time = time.time()
    
    # استدعاء المعالج التالي
    yield
    
    end_time = time.time()
    response_time = end_time - start_time
    
    # تحديث إحصائيات السرعة
    update_speed_stats(response_time)

@bot.message_handler(commands=['start'])
def start(message):
    user_id = message.from_user.id
    user_name = message.from_user.first_name
    
    # الحصول على سرعة استجابة البوت
    speed_info = get_response_speed()
    
    # تنسيق وقت آخر تحديث
    last_check = speed_info['last_check']
    if last_check:
        time_diff = datetime.datetime.now() - last_check
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

    image_url = 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTc_tNTW84d2jsH0ecXzDQRoIWMtNGzv734Kw&usqp=CAU'
    bot.send_photo(message.chat.id, image_url, caption=welcome_message, 
                   reply_markup=create_main_keyboard(), parse_mode='Markdown')

@bot.message_handler(commands=['speed'])
def speed_command(message):
    """أمر لفحص سرعة استجابة البوت"""
    bot.send_message(message.chat.id, "⚡ جاري قياس سرعة استجابة البوت...")
    
    # إجراء فحص جديد
    response_time = measure_response_speed()
    speed_info = get_response_speed()
    
    # إحصائيات آخر 10 قياسات
    last_10_stats = ""
    if speed_info['last_10_responses']:
        last_10_avg = statistics.mean(speed_info['last_10_responses'])
        last_10_min = min(speed_info['last_10_responses'])
        last_10_max = max(speed_info['last_10_responses'])
        
        last_10_stats = (
            "\n\n📈 **إحصائيات آخر 10 قياسات:**\n"
            f"📊 **المتوسط:** {last_10_avg:.3f} ثانية\n"
            f"⚡ **الأسرع:** {last_10_min:.3f} ثانية\n"
            f"🐌 **الأبطأ:** {last_10_max:.3f} ثانية"
        )
    
    speed_message = (
        "📊 **نتيجة قياس سرعة الاستجابة:**\n\n"
        "⚡ **سرعة البوت:** {speed}\n"
        "⏱️ **الاستجابة الأخيرة:** {last:.3f} ثانية\n"
        "📊 **متوسط السرعة:** {avg:.3f} ثانية\n"
        "📈 **أسرع استجابة:** {min:.3f} ثانية\n"
        "📉 **أبطأ استجابة:** {max:.3f} ثانية\n"
        "🔢 **إجمالي القياسات:** {count}\n"
        "🕐 **وقت القياس:** {time}"
        "{last_10_stats}"
    ).format(
        speed=speed_info['speed_category'],
        last=response_time,
        avg=speed_info['avg_response_time'],
        min=speed_info['min_response'],
        max=speed_info['max_response'],
        count=len(speed_info['response_times']),
        time=speed_info['last_check'].strftime("%H:%M:%S") if speed_info['last_check'] else "غير متوفر",
        last_10_stats=last_10_stats
    )
    
    bot.send_message(message.chat.id, speed_message, parse_mode='Markdown')

@bot.message_handler(commands=['ping'])
def ping_command(message):
    """أمر بسيط لفحص سرعة الاستجابة (Ping)"""
    start_time = time.time()
    ping_msg = bot.send_message(message.chat.id, "🏓 بنج...")
    end_time = time.time()
    
    response_time = (end_time - start_time) * 1000  # تحويل إلى ملي ثانية
    
    # تحديث الإحصائيات
    update_speed_stats(response_time / 1000)  # تحويل إلى ثواني
    
    bot.edit_message_text(
        f"🏓 بونج!\n⏱️ سرعة الاستجابة: {response_time:.0f}ms\n⚡ فئة السرعة: {response_speed_info['speed_category']}",
        message.chat.id,
        ping_msg.message_id
    )

def create_main_keyboard():
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("رفع ملف 📤", callback_data='upload'))
    keyboard.add(types.InlineKeyboardButton("عرض جميع الملفات 📂", callback_data='show_files'))
    keyboard.add(types.InlineKeyboardButton("فحص سرعة البوت ⚡", callback_data='check_speed'))
    keyboard.add(types.InlineKeyboardButton("اختبار Ping 🏓", callback_data='ping_test'))
    keyboard.add(types.InlineKeyboardButton("حذف جميع الملفات 🗑️", callback_data='delete_all_files'))
    keyboard.add(types.InlineKeyboardButton("إيقاف جميع الملفات ⏹️", callback_data='stop_all_files'))
    keyboard.add(types.InlineKeyboardButton("إعادة تشغيل جميع الملفات 🔄", callback_data='restart_all_files'))
    return keyboard

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == 'upload':
        bot.send_message(call.message.chat.id, "📤 يرجى إرسال ملف بايثون لي تشغيله.")
        bot.register_next_step_handler(call.message, handle_document)
    elif call.data == 'show_files':
        show_all_files(call.message.chat.id, call.from_user.id)
    elif call.data == 'check_speed':
        speed_command(call.message)
    elif call.data == 'ping_test':
        ping_test_callback(call)
    elif call.data == 'delete_all_files':
        delete_all_files(call.message.chat.id, call.from_user.id)
    elif call.data == 'stop_all_files':
        stop_all_files(call.message.chat.id)
    elif call.data == 'restart_all_files':
        restart_all_files(call.message.chat.id, call.from_user.id)
    elif call.data.startswith('run_'):
        file_name = call.data.split('run_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(call.from_user.id), file_name)
        if os.path.exists(file_path):
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
        file_path = os.path.join(UPLOAD_FOLDER, str(call.from_user.id), file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.send_message(call.message.chat.id, f"🗑️ تم حذف الملف: {file_name}")
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    elif call.data.startswith('restart_'):
        file_name = call.data.split('restart_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(call.from_user.id), file_name)
        if os.path.exists(file_path):
            bot.send_message(call.message.chat.id, f"🔄 تم إعادة تشغيل الملف: {file_name}")
            start_file_thread(file_path, call.message.chat.id)
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    elif call.data.startswith('approve_'):
        file_name = call.data.split('approve_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(call.from_user.id), file_name)
        if os.path.exists(file_path):
            bot.send_message(call.message.chat.id, f"✅ تمت الموافقة على تشغيل الملف: {file_name}")
            start_file_thread(file_path, call.message.chat.id)
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")
    elif call.data.startswith('reject_'):
        file_name = call.data.split('reject_')[1]
        file_path = os.path.join(UPLOAD_FOLDER, str(call.from_user.id), file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            bot.send_message(call.message.chat.id, f"❌ تم رفض الملف: {file_name} وحذفه.")
        else:
            bot.send_message(call.message.chat.id, "❌ الملف غير موجود.")

def ping_test_callback(call):
    """اختبار Ping من خلال الكالي باك"""
    start_time = time.time()
    ping_msg = bot.send_message(call.message.chat.id, "🏓 بنج...")
    end_time = time.time()
    
    response_time = (end_time - start_time) * 1000  # ملي ثانية
    
    # تحديث الإحصائيات
    update_speed_stats(response_time / 1000)
    
    bot.edit_message_text(
        f"🏓 بونج!\n\n"
        f"⏱️ **سرعة الاستجابة:** {response_time:.0f}ms\n"
        f"⚡ **فئة السرعة:** {response_speed_info['speed_category']}\n"
        f"📊 **المتوسط الحالي:** {response_speed_info['avg_response_time']:.3f}s",
        call.message.chat.id,
        ping_msg.message_id,
        parse_mode='Markdown'
    )

# باقي الدوال (show_all_files, show_file_buttons, delete_all_files, stop_all_files, restart_all_files)
# تبقى كما هي بدون تغيير

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    user_name = message.from_user.username
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

        bot.send_message(message.chat.id, "✅ تم رفع الملف بنجاح!")
        show_animated_message(message.chat.id, message.document.file_name)

        keyboard = types.InlineKeyboardMarkup()
        keyboard.add(types.InlineKeyboardButton("موافقة ✅", callback_data=f'approve_{message.document.file_name}'))
        keyboard.add(types.InlineKeyboardButton("رفض ❌", callback_data=f'reject_{message.document.file_name}'))
        bot.send_document(OWNER_ID, open(file_path, 'rb'), 
                         caption=f"📤 تم رفع ملف جديد من:\n👤 الاسم: {full_name}\n🆔 المعرف: {user_id}\n📱 @{user_name}\n📁 الملف: {message.document.file_name}\n\nمطور البوت: Sifo (@S_sifo)", 
                         reply_markup=keyboard)

        bot.send_message(message.chat.id, "📤 تم إرسال الملف إلى المالك للتحقق. يرجى الانتظار...")

# باقي الدوال (start_file_thread, run_file, monitor_process, notify_owner)
# تبقى كما هي بدون تغيير

# دالة للفحص الدوري لسرعة الاستجابة
def periodic_response_check():
    """فحص دوري لسرعة استجابة البوت"""
    while True:
        time.sleep(60)  # كل دقيقة
        try:
            measure_response_speed()
            print(f"✅ تم تحديث سرعة الاستجابة: {response_speed_info['speed_category']} ({response_speed_info['avg_response_time']:.3f}s)")
        except Exception as e:
            print(f"⚠️ خطأ في الفحص الدوري للسرعة: {e}")

# بدء الفحص الدوري في خيط منفصل
response_check_thread = threading.Thread(target=periodic_response_check)
response_check_thread.daemon = True
response_check_thread.start()

# تشغيل البوت
def run_bot():
    while True:
        try:
            # قياس السرعة الأولي
            measure_response_speed()
            print(f"🚀 بدء تشغيل البوت... سرعة الاستجابة: {response_speed_info['speed_category']}")
            
            bot.polling(none_stop=True)
        except Exception as e:
            print(f"⚠️ حدث خطأ: {e}. إعادة المحاولة خلال 10 ثوانٍ...")
            time.sleep(10)

if __name__ == "__main__":
    run_bot()