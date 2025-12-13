import telebot
import subprocess
import os
import zipfile
import tempfile
import shutil
import requests
import re
import logging
from telebot import types
import time
import json
import sys

# ==================== الإعدادات ====================
TOKEN = '8156912979:AAHyLYBEM7GBOfFjvwFtJ9Cxkg4uEqxUFLY'  # ضع توكن البوت الخاص بك هنا
ADMIN_ID = 7627857345  # تأكد من أن هذا الرقم بدون علامات اقتباس
CHANNEL_USERNAME = '@pythonyemen1'  # يوزر قناتك هنا (مع @)
# ================================================

# إعداد تسجيل الأخطاء
logging.basicConfig(level=logging.INFO)

# إنشاء المجلدات والملفات اللازمة إن لم تكن موجودة
if not os.path.exists('uploaded_bots'):
    os.makedirs('uploaded_bots')

# دالة لتحميل البيانات من ملف JSON
def load_data(filename):
    try:
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Error loading {filename}: {e}")
    return []

# دالة لحفظ البيانات في ملف JSON
def save_data(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        logging.error(f"Error saving to {filename}: {e}")

# تحميل قوائم المستخدمين
VIP_USERS = load_data('vip_users.json')
BANNED_USERS = load_data('banned_users.json')
APPROVED_USERS = load_data('approved_users.json')
PENDING_REQUESTS = load_data('pending_requests.json')

bot = telebot.TeleBot(TOKEN)
bot_scripts = {}

# ======== دوال التحقق من الاشتراك والصلاحيات ========

def is_admin(user_id):
    try:
        # التأكد من مقارنة الأرقام الصحيحة
        return int(user_id) == int(ADMIN_ID)
    except (ValueError, TypeError):
        return False

def check_subscription(user_id):
    try:
        member = bot.get_chat_member(CHANNEL_USERNAME, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except telebot.apihelper.ApiException as e:
        # التعامل مع الأخطاء المختلفة
        return True

def user_has_access(user_id):
    return is_admin(user_id) or user_id in VIP_USERS or user_id in APPROVED_USERS

def ask_for_subscription(chat_id):
    markup = types.InlineKeyboardMarkup()
    join_button = types.InlineKeyboardButton('📢 اشترك في القناة', url=f'https://t.me/{CHANNEL_USERNAME.replace("@", "")}')
    check_button = types.InlineKeyboardButton('✅ تحقق من الاشتراك', callback_data='check_subscription')
    markup.add(join_button, check_button)
    bot.send_message(chat_id, f"📢 عزيزي المستخدم، عليك الاشتراك في القناة {CHANNEL_USERNAME} لتتمكن من استخدام البوت.", reply_markup=markup)

def request_access_message(chat_id):
    markup = types.InlineKeyboardMarkup()
    request_button = types.InlineKeyboardButton('🔐 إرسال طلب للمدير', callback_data='request_access')
    markup.add(request_button)
    bot.send_message(chat_id, "✋ أهلاً بك! لاستخدام هذا البوت، يجب أن يوافق المدير على طلبك. اضغط على الزر أدناه لإرسال طلب.", reply_markup=markup)

# ======== معالجات الأوامر والرسائل ========

@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_id = message.from_user.id
    chat_id = message.chat.id

    if user_id in BANNED_USERS:
        bot.send_message(chat_id, "❌ أنت محظور من استخدام هذا البوت.")
        return

    if not check_subscription(user_id):
        ask_for_subscription(chat_id)
        return

    if not user_has_access(user_id):
        if user_id not in PENDING_REQUESTS:
            request_access_message(chat_id)
        else:
            bot.send_message(chat_id, "⏳ لقد أرسلت طلبًا بالفعل. يرجى انتظار موافقة المدير.")
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    upload_button = types.InlineKeyboardButton('📤 رفع ملف', callback_data='upload')
    install_lib_button = types.InlineKeyboardButton('📚 تثبيت مكتبة', callback_data='install_library')
    dev_channel_button = types.InlineKeyboardButton('🔧 قناة المطور', url='https://t.me/UXD_5')
    speed_button = types.InlineKeyboardButton('⚡ سرعة البوت', callback_data='speed')
    
    markup.add(upload_button, install_lib_button)
    markup.add(speed_button, dev_channel_button)
    
    if is_admin(user_id):
        admin_panel_button = types.InlineKeyboardButton('👑 لوحة التحكم', callback_data='admin_panel')
        markup.add(admin_panel_button)

    bot.send_message(chat_id, f"مرحباً، {message.from_user.first_name}! 👋\nيمكنك رفع ملفات استضافه : zip |  py  \n✨ يمكنك استخدام الأزرار أدناه للتحكم:", reply_markup=markup)

@bot.message_handler(commands=['admin'])
def admin_command(message):
    if not is_admin(message.from_user.id):
        bot.reply_to(message, "⚠️ هذه الأوامر خاصة بالمدير فقط.")
        return
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    ban_button = types.InlineKeyboardButton("🚫 حظر مستخدم", callback_data="admin_ban")
    unban_button = types.InlineKeyboardButton("✅ إلغاء حظر", callback_data="admin_unban")
    promote_button = types.InlineKeyboardButton("⭐ ترقية لـ VIP", callback_data="admin_promote")
    demote_button = types.InlineKeyboardButton("⬇️ إزالة من VIP", callback_data="admin_demote")
    requests_button = types.InlineKeyboardButton(f"📥 الطلبات ({len(PENDING_REQUESTS)})", callback_data="admin_requests")
    
    markup.add(ban_button, unban_button, promote_button, demote_button, requests_button)
    bot.send_message(message.chat.id, "👑 لوحة تحكم المدير:", reply_markup=markup)

@bot.message_handler(content_types=['document'])
def handle_file(message):
    user_id = message.from_user.id
    if user_id in BANNED_USERS:
        bot.send_message(message.chat.id, "❌ أنت محظور من استخدام هذا البوت.")
        return
    if not check_subscription(user_id):
        ask_for_subscription(message.chat.id)
        return
    if not user_has_access(user_id):
        bot.send_message(message.chat.id, "⚠️ ليس لديك صلاحية لرفع الملفات. يرجى طلب الوصول من المدير.")
        return
    try:
        file_id = message.document.file_id
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        file_name = message.document.file_name
        if file_name.endswith('.zip'):
            with tempfile.TemporaryDirectory() as temp_dir:
                zip_folder_path = os.path.join(temp_dir, file_name.split('.')[0])
                zip_path = os.path.join(temp_dir, file_name)
                with open(zip_path, 'wb') as new_file:
                    new_file.write(downloaded_file)
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(zip_folder_path)
                final_folder_path = os.path.join('uploaded_bots', file_name.split('.')[0])
                if os.path.exists(final_folder_path):
                    shutil.rmtree(final_folder_path)
                shutil.copytree(zip_folder_path, final_folder_path)
                main_file_path = find_main_file(final_folder_path)
                if main_file_path:
                    run_script(main_file_path, message.chat.id, os.path.basename(main_file_path), message)
                else:
                    bot.send_message(message.chat.id, "❓ لم أتمكن من العثور على bot.py أو run.py. أرسل اسم الملف الرئيسي لتشغيله:")
                    bot.register_next_step_handler(message, lambda m: get_custom_file_to_run(m, final_folder_path))
        elif file_name.endswith('.py'):
            script_path = os.path.join('uploaded_bots', file_name)
            with open(script_path, 'wb') as new_file:
                new_file.write(downloaded_file)
            run_script(script_path, message.chat.id, file_name, message)
        else:
            bot.reply_to(message, "⚠️ هذا البوت خاص برفع ملفات بايثون أو zip فقط.")
    except Exception as e:
        bot.reply_to(message, f"❌ حدث خطأ: {e}")
        logging.error(f"Error handling file: {e}")

def find_main_file(folder_path):
    if os.path.exists(os.path.join(folder_path, 'run.py')):
        return os.path.join(folder_path, 'run.py')
    if os.path.exists(os.path.join(folder_path, 'bot.py')):
        return os.path.join(folder_path, 'bot.py')
    return None

def get_custom_file_to_run(message, folder_path):
    try:
        custom_file_path = os.path.join(folder_path, message.text)
        if os.path.exists(custom_file_path):
            run_script(custom_file_path, message.chat.id, message.text, message)
        else:
            bot.send_message(message.chat.id, "❌ الملف الذي حددته غير موجود. تأكد من الاسم وحاول مرة أخرى.")
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ حدث خطأ: {e}")

def run_script(script_path, chat_id, file_name, original_message):
    if chat_id in bot_scripts and bot_scripts[chat_id].get('process'):
        stop_running_bot(chat_id)
    max_retries = 5
    for attempt in range(max_retries):
        try:
            bot.send_message(chat_id, f"🚀 [محاولة {attempt + 1}/{max_retries}] جارٍ تشغيل البوت {file_name}...")
            process = subprocess.Popen(
                [sys.executable, '-u', script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8'
            )
            time.sleep(4)
            if process.poll() is not None:
                stderr_output = process.stderr.read()
                missing_module_match = re.search(r"ModuleNotFoundError: No module named '([\w\.]+)'", stderr_output)
                if missing_module_match:
                    module_name = missing_module_match.group(1).strip("'\"")
                    bot.send_message(chat_id, f"⚠️ تم اكتشاف مكتبة ناقصة: `{module_name}`. جاري تثبيتها تلقائيًا...")
                    try:
                        subprocess.check_call([sys.executable, '-m', 'pip', 'install', module_name])
                        bot.send_message(chat_id, f"✅ تم تثبيت `{module_name}` بنجاح. إعادة محاولة التشغيل...")
                        continue
                    except subprocess.CalledProcessError as e:
                        bot.send_message(chat_id, f"❌ فشل تثبيت المكتبة `{module_name}`.\n`{e}`")
                        return
                else:
                    error_message = stderr_output if stderr_output else "فشل تشغيل البوت لسبب غير معروف."
                    bot.send_message(chat_id, f"❌ فشل تشغيل البوت. الخطأ:\n`{error_message}`")
                    return
            else:
                bot.send_message(chat_id, "✅ يبدو أن البوت يعمل بنجاح!")
                folder_path = os.path.dirname(script_path)
                bot_scripts[chat_id] = {'process': process, 'file_name': file_name, 'folder_path': folder_path}
                user_info = f"@{original_message.from_user.username}" if original_message.from_user.username else str(original_message.from_user.id)
                caption = f"📤 قام المستخدم {user_info} برفع وتشغيل بوت جديد:\n`{file_name}`"
                bot.send_message(ADMIN_ID, caption)
                markup = types.InlineKeyboardMarkup()
                stop_button = types.InlineKeyboardButton("🔴 إيقاف", callback_data=f'stop_{chat_id}')
                delete_button = types.InlineKeyboardButton("🗑️ حذف", callback_data=f'delete_{chat_id}')
                markup.add(stop_button, delete_button)
                bot.send_message(chat_id, "استخدم الأزرار أدناه للتحكم فيه 👇", reply_markup=markup)
                return
        except Exception as e:
            bot.send_message(chat_id, f"❌ حدث خطأ استثنائي أثناء محاولة تشغيل البوت: {e}")
            logging.error(f"Critical error in run_script: {e}")
            return
    bot.send_message(chat_id, f"❌ فشل تشغيل البوت بعد {max_retries} محاولات. يرجى التحقق من كود البوت أو تثبيت المكتبات يدويًا.")

def stop_running_bot(chat_id):
    if chat_id in bot_scripts and bot_scripts[chat_id].get('process'):
        process_info = bot_scripts[chat_id]
        process_info['process'].terminate()
        process_info['process'].wait()
        process_info['process'] = None
        bot.send_message(chat_id, f"🔴 تم إيقاف تشغيل البوت ({process_info['file_name']}).")
    else:
        bot.send_message(chat_id, "⚠️ لا يوجد بوت يعمل حالياً لإيقافه.")

def delete_uploaded_file(chat_id):
    if chat_id in bot_scripts and bot_scripts[chat_id].get('folder_path'):
        stop_running_bot(chat_id)
        folder_path = bot_scripts[chat_id]['folder_path']
        try:
            if os.path.exists(folder_path):
                if os.path.isdir(folder_path) and 'uploaded_bots' in folder_path:
                    shutil.rmtree(folder_path)
                elif os.path.isfile(folder_path):
                    os.remove(folder_path)
                bot.send_message(chat_id, "🗑️ تم حذف الملفات المتعلقة بالبوت بنجاح.")
                del bot_scripts[chat_id]
        except Exception as e:
            bot.send_message(chat_id, f"❌ حدث خطأ أثناء الحذف: {e}")
            logging.error(f"Error deleting path {folder_path}: {e}")
    else:
        bot.send_message(chat_id, "⚠️ لا توجد ملفات لحذفها.")

def process_library_installation(message):
    chat_id = message.chat.id
    library_name = message.text.strip()
    if not library_name:
        bot.send_message(chat_id, "لم تقدم اسم مكتبة. يرجى المحاولة مرة أخرى.")
        return
    msg = bot.send_message(chat_id, f"🔄 جاري محاولة تثبيت المكتبة: `{library_name}`...", parse_mode="Markdown")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', library_name])
        bot.edit_message_text(f"✅ تم تثبيت المكتبة `{library_name}` بنجاح!", chat_id, msg.message_id, parse_mode="Markdown")
    except subprocess.CalledProcessError as e:
        bot.edit_message_text(f"❌ فشل تثبيت المكتبة `{library_name}`. قد يكون الاسم غير صحيح أو أنها مثبتة بالفعل.", chat_id, msg.message_id, parse_mode="Markdown")
        logging.error(f"Failed to install library {library_name}: {e}")

def process_admin_action(message, action):
    chat_id = message.chat.id
    try:
        user_id = int(message.text.strip())
        if action == 'ban':
            if user_id not in BANNED_USERS:
                BANNED_USERS.append(user_id)
                save_data(BANNED_USERS, 'banned_users.json')
                bot.send_message(chat_id, f"🚫 تم حظر المستخدم (ID: {user_id}).")
                bot.send_message(user_id, "❌ تم حظرك من استخدام البوت.")
            else:
                bot.send_message(chat_id, f"⚠️ المستخدم (ID: {user_id}) محظور بالفعل.")
        elif action == 'unban':
            if user_id in BANNED_USERS:
                BANNED_USERS.remove(user_id)
                save_data(BANNED_USERS, 'banned_users.json')
                bot.send_message(chat_id, f"✅ تم إلغاء حظر المستخدم (ID: {user_id}).")
                bot.send_message(user_id, "🎉 تم إلغاء حظرك! يمكنك استخدام البوت الآن.")
            else:
                bot.send_message(chat_id, f"⚠️ المستخدم (ID: {user_id}) غير محظور.")
        elif action == 'promote':
            if user_id not in VIP_USERS:
                VIP_USERS.append(user_id)
                save_data(VIP_USERS, 'vip_users.json')
                bot.send_message(chat_id, f"⭐ تم ترقية المستخدم (ID: {user_id}) إلى VIP.")
                bot.send_message(user_id, "🎉 تهانينا! تمت ترقيتك إلى مستخدم VIP.")
            else:
                bot.send_message(chat_id, f"⚠️ المستخدم (ID: {user_id}) بالفعل VIP.")
        elif action == 'demote':
            if user_id in VIP_USERS:
                VIP_USERS.remove(user_id)
                save_data(VIP_USERS, 'vip_users.json')
                bot.send_message(chat_id, f"⬇️ تم إزالة المستخدم (ID: {user_id}) من VIP.")
                bot.send_message(user_id, "💔 تمت إزالتك من قائمة VIP.")
            else:
                bot.send_message(chat_id, f"⚠️ المستخدم (ID: {user_id}) ليس VIP.")
    except ValueError:
        bot.send_message(chat_id, "❌ يرجى إرسال ID المستخدم كرقم صحيح.")
    except Exception as e:
        bot.send_message(chat_id, f"❌ حدث خطأ: {e}")

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    user_id = call.from_user.id
    chat_id = call.message.chat.id
    data = call.data

    if data.startswith('admin_'):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "🚫 هذا الأمر للمدير فقط!", show_alert=True)
            return
        
        bot.answer_callback_query(call.id, "تم استلام أمر إداري.")
        
        if data == 'admin_panel':
            admin_command(call.message)
        elif data == 'admin_ban':
            bot.send_message(chat_id, "🚫 أرسل معرف المستخدم أو ID للحظر:")
            bot.register_next_step_handler(call.message, lambda m: process_admin_action(m, 'ban'))
        elif data == 'admin_unban':
            bot.send_message(chat_id, "✅ أرسل معرف المستخدم أو ID لإلغاء الحظر:")
            bot.register_next_step_handler(call.message, lambda m: process_admin_action(m, 'unban'))
        elif data == 'admin_promote':
            bot.send_message(chat_id, "⭐ أرسل معرف المستخدم أو ID لترقيته إلى VIP:")
            bot.register_next_step_handler(call.message, lambda m: process_admin_action(m, 'promote'))
        elif data == 'admin_demote':
            bot.send_message(chat_id, "⬇️ أرسل معرف المستخدم أو ID لإزالته من VIP:")
            bot.register_next_step_handler(call.message, lambda m: process_admin_action(m, 'demote'))
        elif data == 'admin_requests':
            if PENDING_REQUESTS:
                for req_id in PENDING_REQUESTS:
                    user = bot.get_chat(req_id)
                    user_info = f"@{user.username}" if user.username else f"ID: {req_id}"
                    markup = types.InlineKeyboardMarkup()
                    markup.add(
                        types.InlineKeyboardButton("✅ موافقة", callback_data=f"approve_{req_id}"),
                        types.InlineKeyboardButton("❌ رفض", callback_data=f"reject_{req_id}")
                    )
                    bot.send_message(chat_id, f"طلب وصول من: {user_info}", reply_markup=markup)
            else:
                bot.send_message(chat_id, "📭 لا توجد طلبات وصول معلقة.")
        return

    elif data == 'request_access':
        if user_id in PENDING_REQUESTS:
            bot.answer_callback_query(call.id, "⏳ طلبك معلق بالفعل.", show_alert=True)
            return

        PENDING_REQUESTS.append(user_id)
        save_data(PENDING_REQUESTS, 'pending_requests.json')
        
        user_info = f"@{call.from_user.username}" if call.from_user.username else f"ID: {user_id}"
        markup = types.InlineKeyboardMarkup()
        approve_button = types.InlineKeyboardButton("✅ موافقة", callback_data=f"approve_{user_id}")
        reject_button = types.InlineKeyboardButton("❌ رفض", callback_data=f"reject_{user_id}")
        markup.add(approve_button, reject_button)
        
        bot.send_message(ADMIN_ID, f"📥 طلب وصول جديد من:\nالمستخدم: {call.from_user.first_name}\nاليوزر: {user_info}", reply_markup=markup)
        bot.edit_message_text("✅ تم إرسال طلبك للمدير بنجاح.", chat_id, call.message.message_id)
        bot.answer_callback_query(call.id, "تم إرسال طلبك!")
        return

    elif data.startswith('approve_'):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "🚫 هذا الأمر للمدير فقط!", show_alert=True)
            return
        
        user_to_approve = int(data.split('_')[1])
        if user_to_approve in PENDING_REQUESTS:
            PENDING_REQUESTS.remove(user_to_approve)
            APPROVED_USERS.append(user_to_approve)
            save_data(PENDING_REQUESTS, 'pending_requests.json')
            save_data(APPROVED_USERS, 'approved_users.json')
            
            bot.edit_message_text(f"✅ تم الموافقة على طلب المستخدم (ID: {user_to_approve}).", chat_id, call.message.message_id)
            bot.send_message(user_to_approve, "🎉 تهانينا! وافق المدير على طلبك. يمكنك الآن استخدام البوت.\nاضغط /start للبدء.")
        else:
            bot.edit_message_text(f"✅ تمت معالجة هذا الطلب مسبقًا.", chat_id, call.message.message_id)
        bot.answer_callback_query(call.id, "تمت الموافقة بنجاح.")
        return

    elif data.startswith('reject_'):
        if not is_admin(user_id):
            bot.answer_callback_query(call.id, "🚫 هذا الأمر للمدير فقط!", show_alert=True)
            return
            
        user_to_reject = int(data.split('_')[1])
        if user_to_reject in PENDING_REQUESTS:
            PENDING_REQUESTS.remove(user_to_reject)
            save_data(PENDING_REQUESTS, 'pending_requests.json')
            
            bot.edit_message_text(f"❌ تم رفض طلب المستخدم (ID: {user_to_reject}).", chat_id, call.message.message_id)
            bot.send_message(user_to_reject, "💔 نأسف، لقد رفض المدير طلبك للوصول إلى البوت.")
        else:
            bot.edit_message_text(f"❌ تمت معالجة هذا الطلب مسبقًا.", chat_id, call.message.message_id)
        bot.answer_callback_query(call.id, "تم الرفض بنجاح.")
        return

    elif data == 'check_subscription':
        if check_subscription(user_id):
            bot.answer_callback_query(call.id, "✅ شكرًا لاشتراكك! اضغط /start مجددًا.", show_alert=True)
            bot.delete_message(chat_id, call.message.message_id)
        else:
            bot.answer_callback_query(call.id, "⚠️ لم تشترك في القناة بعد!", show_alert=True)
        return

    elif data == 'install_library':
        prompt_message = bot.send_message(chat_id, "يرجى إرسال اسم مكتبة بايثون التي تريد تثبيتها (مثال: `pytelegrambotapi`).", parse_mode="Markdown")
        bot.register_next_step_handler(prompt_message, process_library_installation)
        bot.answer_callback_query(call.id)
        return

    elif data.startswith('stop_'):
        target_chat_id = int(data.split('_')[1])
        stop_running_bot(target_chat_id)
        bot.answer_callback_query(call.id, "تم إرسال أمر الإيقاف.")
        bot.edit_message_reply_markup(chat_id, call.message.message_id, reply_markup=None)
        return

    elif data.startswith('delete_'):
        target_chat_id = int(data.split('_')[1])
        delete_uploaded_file(target_chat_id)
        bot.answer_callback_query(call.id, "تم إرسال أمر الحذف.")
        bot.edit_message_reply_markup(chat_id, call.message.message_id, reply_markup=None)
        return

    elif data == 'speed':
        try:
            start_time = time.time()
            bot.get_me()
            latency = time.time() - start_time
            bot.answer_callback_query(call.id, f"⚡ سرعة استجابة البوت: {latency:.2f} ثانية.")
        except Exception as e:
            bot.answer_callback_query(call.id, f"❌ حدث خطأ: {e}")
        return

    elif data == 'upload':
        bot.send_message(chat_id, "📄 من فضلك، أرسل الملف الذي تريد رفعه (zip أو py).")
        bot.answer_callback_query(call.id)
        return

print("Bot is running...")
bot.infinity_polling(skip_pending=True)