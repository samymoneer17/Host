
import telebot
from telebot import types
import os
import time
import subprocess
import threading
import random
import psutil  # لمراقبة العمليات وإدارتها
import ast  # لتحليل الكود
import pyclamd  # للتحقق من الفيروسات
import re  # للتحقق من الأنماط الضارة

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

# تهيئة ClamAV للتحقق من الفيروسات
try:
    cd = pyclamd.ClamdAgnostic()
    cd.ping()  # التحقق من اتصال ClamAV
except Exception as e:
    print(f"⚠️ خطأ في تهيئة ClamAV: {e}")
    cd = None

# دالة للتحقق من وجود أكواد ضارة في الملف
def check_for_malicious_code(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # قائمة بالأوامر الخطرة
        dangerous_patterns = [
            r"os\.system\(", r"subprocess\.", r"eval\(", r"exec\(", r"open\(",
            r"import\s+os", r"import\s+subprocess", r"__import__\(", r"pickle\.",
            r"requests\.", r"urllib\.", r"socket\.", r"shutil\.", r"sys\.exit\("
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, content):
                return True  # يوجد كود ضار
        
        # تحليل الكود باستخدام ast للتأكد من عدم وجود أكواد ضارة
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'open', 'system']:
                            return True  # يوجد كود ضار
        except Exception as e:
            print(f"⚠️ خطأ في تحليل الكود: {e}")
            return True  # في حالة وجود خطأ، نعتبر الملف غير آمن
        
        return False  # الملف آمن
    except Exception as e:
        print(f"⚠️ خطأ في قراءة الملف: {e}")
        return True  # في حالة وجود خطأ، نعتبر الملف غير آمن

# دالة للتحقق من الفيروسات باستخدام ClamAV
def check_for_viruses(file_path):
    if cd:
        try:
            scan_result = cd.scan_file(file_path)
            if scan_result:
                print(f"⚠️ تم اكتشاف فيروس في الملف: {scan_result}")
                return True  # يوجد فيروس
            return False  # لا يوجد فيروس
        except Exception as e:
            print(f"⚠️ خطأ في فحص الملف: {e}")
            return True  # في حالة وجود خطأ، نعتبر الملف غير آمن
    else:
        print("⚠️ ClamAV غير متوفر. سيتم تخطي فحص الفيروسات.")
        return False  # إذا لم يكن ClamAV متوفرًا، نعتبر الملف آمن

# دالة لعرض رسالة متحركة أثناء الفحص
def show_animated_message(chat_id, file_name):
    emojis = ["👀", "👋🏻", "🤝🏻", "🎉", "❤️", "😜", "😇", "😭", "😅", "😱", "🤐", "🤯", "🤒", "🤡", "👻", "😷", "🥴"]
    message = bot.send_message(chat_id, f"جاري فحص الملف {file_name}... {emojis[0]}")
    
    for i in range(1, 10):  # عرض 10 رموز تعبيرية مختلفة
        time.sleep(1)  # الانتظار لمدة ثانية
        bot.edit_message_text(f"جاري فحص الملف {file_name}... {emojis[i % len(emojis)]}", chat_id, message.message_id)
    
    bot.delete_message(chat_id, message.message_id)  # حذف الرسالة المتحركة بعد الانتهاء

bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['start'])
def start(message):
    user_id = message.from_user.id
    user_name = message.from_user.first_name  # الحصول على اسم المستخدم
    welcome_message = (
        "👋🏻 مرحباً بك، {user_name}!\n\n"
        "أنا بوت متعدد الاستخدامات يساعدك في:\n"
        "📤 رفع الملفات بسهولة.\n"
        "⚡ تشغيل الملفات بأمان.\n\n"
        "استخدم الأزرار أدناه للتفاعل مع البوت."
    ).format(user_name=user_name)  # إدراج اسم المستخدم

    # إرسال الصورة مع النص والأزرار في رسالة واحدة  
    image_url = 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTc_tNTW84d2jsH0ecXzDQRoIWMtNGzv734Kw&usqp=CAU'  # استبدل هذا بالرابط الصحيح للصورة  
    bot.send_photo(message.chat.id, image_url, caption=welcome_message, reply_markup=create_main_keyboard(), parse_mode='Markdown')

def create_main_keyboard():
    keyboard = types.InlineKeyboardMarkup()
    keyboard.add(types.InlineKeyboardButton("رفع ملف 📤", callback_data='upload'))
    keyboard.add(types.InlineKeyboardButton("عرض جميع الملفات 📂", callback_data='show_files'))
    keyboard.add(types.InlineKeyboardButton("حذف جميع الملفات 🗑️", callback_data='delete_all_files'))
    keyboard.add(types.InlineKeyboardButton("إيقاف جميع الملفات ⏹️", callback_data='stop_all_files'))
    keyboard.add(types.InlineKeyboardButton("إعادة تشغيل جميع الملفات 🔄", callback_data='restart_all_files'))
    return keyboard

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    if call.data == 'upload':
        bot.send_message(call.message.chat.id, "📤 يرجى إرسال ملف بايثون لي تشغيله.")
        bot.register_next_step_handler(call.message, handle_document)  # انتظار إرسال الملف
    elif call.data == 'show_files':
        show_all_files(call.message.chat.id, call.from_user.id)
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
            process.terminate()  # أو process.kill() حسب الحاجة
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

def delete_all_files(chat_id, user_id):
    user_folder = os.path.join(UPLOAD_FOLDER, str(user_id))
    if os.path.exists(user_folder):
        files = os.listdir(user_folder)
        if files:
            for file_name in files:
                file_path = os.path.join(user_folder, file_name)
                os.remove(file_path)
            bot.send_message(chat_id, "✅ تم حذف جميع الملفات.")
        else:
            bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")
    else:
        bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")

def stop_all_files(chat_id):
    if chat_id in running_processes:
        process = running_processes[chat_id]
        process.terminate()  # أو process.kill() حسب الحاجة
        del running_processes[chat_id]
        bot.send_message(chat_id, "✅ تم إيقاف جميع الملفات.")
    else:
        bot.send_message(chat_id, "❗ لا توجد ملفات قيد التشغيل.")

def restart_all_files(chat_id, user_id):
    user_folder = os.path.join(UPLOAD_FOLDER, str(user_id))
    if os.path.exists(user_folder):
        files = os.listdir(user_folder)
        if files:
            for file_name in files:
                file_path = os.path.join(user_folder, file_name)
                start_file_thread(file_path, chat_id)
            bot.send_message(chat_id, "🔄 تم إعادة تشغيل جميع الملفات.")
        else:
            bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")
    else:
        bot.send_message(chat_id, "❌ لا توجد ملفات مرفوعة.")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    user_name = message.from_user.username  # الحصول على اسم المستخدم
    full_name = message.from_user.first_name + " " + (message.from_user.last_name or "")  # الحصول على الاسم الكامل
    if message.document:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        # حفظ الملف في مسار خاص بالمستخدم  
        user_folder = os.path.join(UPLOAD_FOLDER, str(user_id))  
        if not os.path.exists(user_folder):  
            os.makedirs(user_folder)  

        file_path = os.path.join(user_folder, message.document.file_name)  
        with open(file_path, 'wb') as new_file:  
            new_file.write(downloaded_file)  

        if user_id not in user_files:  
            user_files[user_id] = []  
        user_files[user_id].append(message.document.file_name)  # تأكد من إضافة الملف للقاموس  

        bot.send_message(message.chat.id, "✅ تم رفع الملف بنجاح!")  

        # عرض رسالة متحركة أثناء الفحص
        show_animated_message(message.chat.id, message.document.file_name)

        # إرسال الملف إلى المالك مع زر التحكم
        keyboard = types.InlineKeyboardMarkup()
        keyboard.add(types.InlineKeyboardButton("موافقة ✅", callback_data=f'approve_{message.document.file_name}'))
        keyboard.add(types.InlineKeyboardButton("رفض ❌", callback_data=f'reject_{message.document.file_name}'))
        bot.send_document(OWNER_ID, open(file_path, 'rb'), caption=f"📤 تم رفع ملف جديد من:\n👤 الاسم: {full_name}\n🆔 المعرف: {user_id}\n📱 اسم المستخدم: @{user_name}\n📁 الملف: {message.document.file_name}\n\nمطور البوت: Sifo (@S_sifo)", reply_markup=keyboard)

        bot.send_message(message.chat.id, "📤 تم إرسال الملف إلى المالك للتحقق. يرجى الانتظار...")

def start_file_thread(file_path, chat_id):
    thread = threading.Thread(target=run_file, args=(file_path, chat_id))
    thread.start()

def run_file(file_path, chat_id):
    try:
        process = subprocess.Popen(['python', file_path])  # أو الأمر المناسب لتشغيل الملف
        running_processes[chat_id] = process
        bot.send_message(chat_id, "🚀 الملف قيد التشغيل.")

        # توجيه الملف إلى المالك مع المعلومات  
        notify_owner(f"🚀 تم تشغيل ملف جديد من:\n👤 الاسم: {chat_id}\n📁 الملف: {os.path.basename(file_path)}", file_path)  

        # مراقبة العملية للتأكد من استمراريتها
        monitor_process(process, chat_id, file_path)
    except Exception as e:  
        bot.send_message(chat_id, f"⚠️ حدث خطأ أثناء تشغيل الملف: {e}")

def monitor_process(process, chat_id, file_path):
    while True:
        time.sleep(10)  # التحقق كل 10 ثوانٍ
        if process.poll() is not None:  # إذا انتهت العملية
            bot.send_message(chat_id, f"⚠️ الملف {os.path.basename(file_path)} توقف. جاري إعادة التشغيل...")
            run_file(file_path, chat_id)  # إعادة تشغيل الملف
            break

def notify_owner(message, file_path=None):
    if file_path:
        with open(file_path, 'rb') as file:
            bot.send_document(OWNER_ID, file, caption=message)
    else:
        bot.send_message(OWNER_ID, message)

# تشغيل البوت مع إعادة المحاولة عند التعطل
def run_bot():
    while True:
        try:
            bot.polling(none_stop=True)
        except Exception as e:
            print(f"⚠️ حدث خطأ: {e}. إعادة المحاولة خلال 10 ثوانٍ...")
            time.sleep(10)

if __name__ == "__main__":
    run_bot()
