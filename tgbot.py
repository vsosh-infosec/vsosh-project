import os, json, threading
from datetime import datetime
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv
import yaml
from static import StaticAnalyzer

load_dotenv()
bot = telebot.TeleBot(os.getenv("BOT_TOKEN"))
DOWNLOAD_FOLDER = "downloads"
USERS_FILE = "allowed_users.json"

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

static_analyzer = StaticAnalyzer(config_path="config.yaml")
DYNAMIC_ENABLED = ARM64_ENABLED = X64_ENABLED = False
dynamic_analyzer = None

try:
    from dynamic import DynamicAnalyzer
    from vm_manager.vm_config import VMArchitecture
    dynamic_analyzer = DynamicAnalyzer(timeout=30, db_path="logs/dynamic_analysis.db")
    if dynamic_analyzer._vm_manager:
        vm = dynamic_analyzer._vm_manager
        ARM64_ENABLED = vm.config.arm64_config and os.path.exists(vm.config.arm64_config.image_path)
        X64_ENABLED = vm.config.x64_config and os.path.exists(vm.config.x64_config.image_path)
        DYNAMIC_ENABLED = ARM64_ENABLED or X64_ENABLED
    if DYNAMIC_ENABLED:
        print(f"VM: ARM64={'OK' if ARM64_ENABLED else '-'} X64={'OK' if X64_ENABLED else '-'}")
        def warmup():
            if dynamic_analyzer._vm_pool:
                archs = []
                if ARM64_ENABLED: archs.append(VMArchitecture.ARM64)
                if X64_ENABLED: archs.append(VMArchitecture.X64)
                for a, ok in dynamic_analyzer._vm_pool.warmup(architectures=archs, blocking=True).items():
                    print(f"VM {a.value}: {'ready' if ok else 'fail'}")
        threading.Thread(target=warmup, daemon=True).start()
except (ImportError, RuntimeError) as e:
    print(f"Dynamic disabled: {e}")

def load_users():
    if not os.path.exists(USERS_FILE):
        data = {"users": [], "admin": [], "privat_admin": [], "allowed_groups": []}
        save_users(data)
        return data
    with open(USERS_FILE, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return {"users": data, "admin": [], "privat_admin": [], "allowed_groups": []}
    for k in ["users", "admin", "privat_admin", "allowed_groups"]:
        data.setdefault(k, [])
    return data

def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

USER_DATA = load_users()
PRIVATE_ADMINS = USER_DATA["privat_admin"]
ADMINS = USER_DATA["admin"]
ALL_USERS = USER_DATA["users"]
ALLOWED_USERS = list(set(PRIVATE_ADMINS + ADMINS))
ALLOWED_GROUPS = USER_DATA["allowed_groups"]

is_admin = lambda uid: uid in PRIVATE_ADMINS
has_access = lambda uid: uid in ALLOWED_USERS
is_group = lambda msg: msg.chat.type in ['group', 'supergroup']

def get_folder(uid, grp=False):
    name = f"group_{abs(uid)}" if grp else str(uid)
    folder = os.path.join(DOWNLOAD_FOLDER, name)
    os.makedirs(folder, exist_ok=True)
    return folder

def get_files(folder):
    return sorted([f for f in os.listdir(folder) if not f.startswith(".")])

def main_kb(uid):
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("Файлы", callback_data="files"))
    if is_admin(uid):
        kb.row(InlineKeyboardButton("Админ", callback_data="admin_panel"))
    return kb

def admin_kb():
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("+ Админ", callback_data="add_admin"), InlineKeyboardButton("+ Супер", callback_data="add_padmin"))
    kb.row(InlineKeyboardButton("Бан", callback_data="block"), InlineKeyboardButton("Список", callback_data="list"))
    kb.row(InlineKeyboardButton("+ Группа", callback_data="add_grp"), InlineKeyboardButton("- Группа", callback_data="del_grp"))
    kb.row(InlineKeyboardButton("Назад", callback_data="back"))
    return kb

def files_kb(uid, grp=False):
    kb = InlineKeyboardMarkup()
    folder = get_folder(uid, grp)
    files = get_files(folder)
    prefix = "gf:" if grp else "f:"
    if not files:
        kb.row(InlineKeyboardButton("Пусто", callback_data="x"))
    else:
        for i, f in enumerate(files):
            name = f if len(f) < 25 else f[:22] + "..."
            kb.row(InlineKeyboardButton(name, callback_data=f"{prefix}{i}"))
    kb.row(InlineKeyboardButton("Назад", callback_data="gback" if grp else "back"))
    return kb

def file_kb(idx, grp=False):
    kb = InlineKeyboardMarkup()
    p = "g" if grp else ""
    if DYNAMIC_ENABLED:
        kb.row(InlineKeyboardButton("Динамический", callback_data=f"{p}full:{idx}"), InlineKeyboardButton("Статический", callback_data=f"{p}stat:{idx}"))
    else:
        kb.row(InlineKeyboardButton("Анализ", callback_data=f"{p}stat:{idx}"))
    kb.row(InlineKeyboardButton("Удалить", callback_data=f"{p}del:{idx}"), InlineKeyboardButton("Назад", callback_data="gfiles" if grp else "files"))
    return kb

def group_kb():
    kb = InlineKeyboardMarkup()
    kb.row(InlineKeyboardButton("Файлы", callback_data="gfiles"))
    return kb

def run_static(path):
    try:
        return static_analyzer.run(path)
    except Exception as e:
        return {"error": str(e), "verdict": "ERROR", "score": 0}

def run_dynamic(path):
    if not DYNAMIC_ENABLED:
        return {"error": "Недоступно"}
    try:
        return dynamic_analyzer.run(path)
    except Exception as e:
        return {"error": str(e)}

def fmt_report(res, fname, dyn=None):
    v, s = res.get("verdict", "?"), res.get("score", 0)
    e = {"Чистый": "✓", "Подозрительный": "!", "Вредоносное ПО": "X"}.get(v, "?")
    r = f"{e} `{fname}`\nВердикт: {v} | {s}\n"
    if res.get("yara_matches"):
        r += f"YARA: {', '.join(res['yara_matches'][:2])}\n"
    if res.get("clamav", {}).get("infected"):
        r += f"ClamAV: {res['clamav']['signature']}\n"
    if res.get("hash"):
        r += f"SHA256: `{res['hash'][:16]}...`\n"
    if dyn and not dyn.get("error"):
        arch = dyn.get('sandbox', {}).get('architecture', '')
        vm = "X64" if 'x64' in str(arch).lower() else "ARM64"
        r += f"\nДинамика: {dyn['verdict']} | {dyn['threat_score']} | {dyn['duration']:.1f}s"
        if dyn.get('vm_used'): r += f" | {vm}"
        if dyn.get('reasons'):
            r += "\n" + "\n".join(f"• {x[:50]}" for x in dyn['reasons'][:2])
        total = s + dyn['threat_score']
        fv = "X" if total >= 70 else "!" if total >= 40 else "✓"
        r += f"\n\nИтог: {fv} ({total})"
    return r

def extract_file(msg):
    if msg.document: return msg.document.file_id, msg.document.file_name
    if msg.photo: return msg.photo[-1].file_id, f"photo_{msg.photo[-1].file_unique_id}.jpg"
    if msg.video: return msg.video.file_id, msg.video.file_name or f"video_{msg.video.file_unique_id}.mp4"
    if msg.audio: return msg.audio.file_id, msg.audio.file_name or f"audio_{msg.audio.file_unique_id}.mp3"
    if msg.voice: return msg.voice.file_id, f"voice_{msg.voice.file_unique_id}.ogg"
    return None, None

def admin_action(msg, action):
    try:
        val = int(msg.text.strip())
    except ValueError:
        bot.send_message(msg.chat.id, "Нужно число")
        return show_main(msg)
    if action == "add_admin":
        if val not in ADMINS:
            USER_DATA["admin"].append(val)
            ADMINS.append(val)
            ALLOWED_USERS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"+ {val}")
        else:
            bot.send_message(msg.chat.id, "Уже есть")
    elif action == "add_padmin":
        if val not in PRIVATE_ADMINS:
            USER_DATA["privat_admin"].append(val)
            PRIVATE_ADMINS.append(val)
            if val not in ALLOWED_USERS: ALLOWED_USERS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"+ супер {val}")
        else:
            bot.send_message(msg.chat.id, "Уже есть")
    elif action == "block":
        if val in PRIVATE_ADMINS:
            bot.send_message(msg.chat.id, "Нельзя")
        elif val in ALLOWED_USERS:
            if val in USER_DATA["admin"]:
                USER_DATA["admin"].remove(val)
                ADMINS.remove(val)
            ALLOWED_USERS.remove(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"Бан {val}")
        else:
            bot.send_message(msg.chat.id, "Не найден")
    elif action == "add_grp":
        if val >= 0:
            bot.send_message(msg.chat.id, "ID < 0")
        elif val in ALLOWED_GROUPS:
            bot.send_message(msg.chat.id, "Уже есть")
        else:
            USER_DATA["allowed_groups"].append(val)
            ALLOWED_GROUPS.append(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"+ группа {val}")
    elif action == "del_grp":
        if val in ALLOWED_GROUPS:
            USER_DATA["allowed_groups"].remove(val)
            ALLOWED_GROUPS.remove(val)
            save_users(USER_DATA)
            bot.send_message(msg.chat.id, f"- группа {val}")
        else:
            bot.send_message(msg.chat.id, "Не найдена")
    show_main(msg)

def show_main(msg):
    bot.send_message(msg.chat.id, "Malware Inspector\nОтправьте файл", reply_markup=main_kb(msg.from_user.id), parse_mode="Markdown")

@bot.message_handler(commands=["start"])
def cmd_start(msg):
    uid, cid = msg.from_user.id, msg.chat.id
    if is_group(msg):
        if cid not in ALLOWED_GROUPS:
            bot.reply_to(msg, "Группа не авторизована")
            return
        bot.send_message(cid, "Malware Inspector", reply_markup=group_kb(), parse_mode="Markdown")
        return
    if uid not in ALL_USERS:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
    if has_access(uid):
        bot.send_message(uid, "Malware Inspector\nОтправьте файл", reply_markup=main_kb(uid), parse_mode="Markdown")
    else:
        bot.send_message(uid, "Нет доступа")

@bot.message_handler(commands=["myid"])
def cmd_myid(msg):
    bot.reply_to(msg, f"ID: `{msg.from_user.id}`", parse_mode="Markdown")

@bot.message_handler(commands=["groupid"])
def cmd_gid(msg):
    if not is_admin(msg.from_user.id): return
    cid = msg.chat.id
    bot.reply_to(msg, f"ID: `{cid}` {'✓' if cid in ALLOWED_GROUPS else ''}", parse_mode="Markdown")

@bot.message_handler(commands=["admin"])
def cmd_admin(msg):
    uid = msg.from_user.id
    if is_group(msg) or not is_admin(uid): return
    bot.send_message(msg.chat.id, f"Админ | S:{len(PRIVATE_ADMINS)} A:{len(ADMINS)} G:{len(ALLOWED_GROUPS)}", reply_markup=admin_kb(), parse_mode="Markdown")

@bot.message_handler(content_types=["document", "photo", "video", "audio", "voice"])
def handle_file(msg):
    uid, cid = msg.from_user.id, msg.chat.id
    grp = is_group(msg)
    if grp:
        if cid not in ALLOWED_GROUPS: return
        folder = get_folder(cid, True)
    else:
        if not has_access(uid): return
        folder = get_folder(uid)
    file_id, fname = extract_file(msg)
    if not file_id: return
    try:
        status = bot.reply_to(msg, "...")
        info = bot.get_file(file_id)
        data = bot.download_file(info.file_path)
        path = os.path.join(folder, fname)
        with open(path, "wb") as f:
            f.write(data)
        res = run_static(path)
        v, s = res.get("verdict", "?"), res.get("score", 0)
        e = {"Чистый": "✓", "Подозрительный": "!", "Вредоносное ПО": "X"}.get(v, "?")
        report = f"{e} `{fname}` | {v} | {s}"
        files = get_files(folder)
        idx = files.index(fname) if fname in files else 0
        bot.edit_message_text(report, cid, status.message_id, parse_mode="Markdown", reply_markup=file_kb(idx, grp))
    except Exception as e:
        bot.reply_to(msg, f"Ошибка: {e}")

@bot.callback_query_handler(func=lambda c: True)
def on_cb(call):
    uid, cid = call.from_user.id, call.message.chat.id
    d = call.data
    if uid not in ALL_USERS:
        USER_DATA["users"].append(uid)
        ALL_USERS.append(uid)
        save_users(USER_DATA)
    if not has_access(uid) and not d.startswith("g") and d not in ["x"]:
        bot.answer_callback_query(call.id, "Нет доступа")
        return
    grp = d.startswith("g") and d != "grp"
    if d == "back":
        bot.edit_message_text("Malware Inspector", cid, call.message.message_id, reply_markup=main_kb(uid), parse_mode="Markdown")
    elif d == "gback":
        bot.edit_message_text("Malware Inspector", cid, call.message.message_id, reply_markup=group_kb(), parse_mode="Markdown")
    elif d == "files":
        bot.edit_message_text("Файлы:", cid, call.message.message_id, reply_markup=files_kb(uid), parse_mode="Markdown")
    elif d == "gfiles":
        bot.edit_message_text("Файлы группы:", cid, call.message.message_id, reply_markup=files_kb(cid, True), parse_mode="Markdown")
    elif d.startswith("f:") or d.startswith("gf:"):
        grp = d.startswith("gf:")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if grp else uid, grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Нет")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        sz = f"{os.path.getsize(path)/1024/1024:.1f}M" if os.path.exists(path) else "?"
        dt = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%d.%m %H:%M") if os.path.exists(path) else "?"
        bot.edit_message_text(f"`{fname}`\n{sz} | {dt}", cid, call.message.message_id, reply_markup=file_kb(idx, grp), parse_mode="Markdown")
    elif d.startswith("stat:") or d.startswith("gstat:"):
        grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if grp else uid, grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Нет")
            return
        fname = files[idx]
        bot.edit_message_text(f"Анализ `{fname}`...", cid, call.message.message_id, parse_mode="Markdown")
        res = run_static(os.path.join(folder, fname))
        bot.edit_message_text(fmt_report(res, fname), cid, call.message.message_id, reply_markup=file_kb(idx, grp), parse_mode="Markdown")
    elif d.startswith("full:") or d.startswith("gfull:"):
        grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if grp else uid, grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Нет")
            return
        fname = files[idx]
        path = os.path.join(folder, fname)
        if not DYNAMIC_ENABLED:
            bot.answer_callback_query(call.id, "Недоступно")
            return
        bot.edit_message_text(f"Полный анализ `{fname}`...", cid, call.message.message_id, parse_mode="Markdown")
        res = run_static(path)
        dyn = run_dynamic(path)
        bot.edit_message_text(fmt_report(res, fname, dyn), cid, call.message.message_id, reply_markup=file_kb(idx, grp), parse_mode="Markdown")
    elif d.startswith("del:") or d.startswith("gdel:"):
        grp = d.startswith("g")
        idx = int(d.split(":")[1])
        folder = get_folder(cid if grp else uid, grp)
        files = get_files(folder)
        if not (0 <= idx < len(files)):
            bot.answer_callback_query(call.id, "Нет")
            return
        path = os.path.join(folder, files[idx])
        if os.path.exists(path): os.remove(path)
        bot.answer_callback_query(call.id, "Удалено")
        bot.edit_message_text("Файлы:", cid, call.message.message_id, reply_markup=files_kb(cid if grp else uid, grp), parse_mode="Markdown")
    elif d == "admin_panel":
        if call.message.chat.type != 'private' or not is_admin(uid):
            bot.answer_callback_query(call.id, "Нет")
            return
        bot.edit_message_text(f"Админ | S:{len(PRIVATE_ADMINS)} A:{len(ADMINS)} G:{len(ALLOWED_GROUPS)}", cid, call.message.message_id, reply_markup=admin_kb(), parse_mode="Markdown")
    elif d == "list":
        if call.message.chat.type != 'private' or not is_admin(uid): return
        t = f"S: {PRIVATE_ADMINS[:3]}\nA: {ADMINS[:3]}\nG: {ALLOWED_GROUPS[:3]}"
        bot.edit_message_text(t, cid, call.message.message_id, reply_markup=admin_kb(), parse_mode="Markdown")
    elif d in ["add_admin", "add_padmin", "block", "add_grp", "del_grp"]:
        if call.message.chat.type != 'private' or not is_admin(uid):
            bot.answer_callback_query(call.id, "Нет")
            return
        prompts = {"add_admin": "ID:", "add_padmin": "ID супер:", "block": "ID бан:", "add_grp": "ID группы:", "del_grp": "ID удалить:"}
        m = bot.send_message(cid, prompts[d])
        bot.register_next_step_handler(m, lambda msg: admin_action(msg, d))
    elif d == "x":
        bot.answer_callback_query(call.id)

if __name__ == "__main__":
    os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    print("Bot started")
    bot.infinity_polling()
