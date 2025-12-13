# /sdcard/Onyx/main.py
# Onyx — CLI (устойчив к ошибкам локализации)

import os
import json
import getpass
import subprocess
import random
import string
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets

# --- Пути ---
config_dir = "/sdcard/Onyx/config"
settings_file = os.path.join(config_dir, "settings.json")
data_file = "/sdcard/Onyx/data/vault.enc"
key_file = "/sdcard/Onyx/data/key.key"
locales_dir = "/sdcard/Onyx/locales"
os.makedirs(config_dir, exist_ok=True)
os.makedirs(os.path.dirname(data_file), exist_ok=True)

# --- Настройки по умолчанию ---
DEFAULT_SETTINGS = {"language": "ru"}

DEFAULT_TRANSLATIONS = {
    "app_title": "Onyx",
    "enter_master": "Enter master password",
    "login": "Login",
    "password": "Password",
    "service": "Service",
    "add_password": "➕ Add password",
    "view_passwords": "📋 View passwords",
    "no_passwords": "No saved passwords",
    "copy_login": "📋 Copy login",
    "copy_password": "🔑 Copy password",
    "copied": "Copied!",
    "show": "👁 Show",
    "hide": "🙈 Hide",
    "close": "Close",
    "settings": "⚙️ Settings",
    "language": "🌐 Language",
    "choose_language": "Choose language",
    "save": "Save",
    "restart_required": "Restart to apply language",
    "generate": "🎲 Generate",
    "check": "🔍 Check",
    "weak_password": "⚠️ Weak password!",
    "strong_password": "✅ Strong password"
}

# --- Загрузка настроек ---
def load_settings():
    try:
        if os.path.exists(settings_file):
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Убедимся, что language есть
            if "language" not in data:
                data["language"] = "ru"
                save_settings(data)
            return data
    except:
        pass
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    try:
        with open(settings_file, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"❌ Не удалось сохранить настройки: {e}")

# --- Загрузка перевода ---
def load_translation():
    settings = load_settings()
    lang_code = settings.get("language", "ru")
    locale_path = os.path.join(locales_dir, f"{lang_code}.json")
    
    # Попробуем загрузить перевод
    try:
        if os.path.exists(locale_path):
            with open(locale_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Объединим с дефолтами — на всякий случай
            result = DEFAULT_TRANSLATIONS.copy()
            result.update(data)
            return result
    except:
        pass
    
    # Если не получилось — возвращаем дефолтный русский
    return DEFAULT_TRANSLATIONS.copy()

# --- Гарантированная функция перевода ---
def safe_get(key: str) -> str:
    return _.get(key, DEFAULT_TRANSLATIONS.get(key, key))

# --- Инициализация перевода ---
_ = load_translation()

# --- Ключ из мастер-пароля ---
def derive_key(password: str, salt: bytes) -> bytes:
    key = password.encode()
    for i in range(100_000):
        key = sha256(key + salt + i.to_bytes(4, 'big')).digest()
    return key[:32]

# --- Шифрование ---
def encrypt_data(data: str, key: bytes) -> dict:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return {"iv": iv.hex(), "ciphertext": ciphertext.hex()}

def decrypt_data(encrypted: dict, key: bytes) -> str:
    iv = bytes.fromhex(encrypted["iv"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(ciphertext)
    data = unpad(padded_data, AES.block_size)
    return data.decode()

# --- Хранилище ---
master_password = None

def load_vault():
    if not os.path.exists(data_file):
        return {}
    try:
        with open(key_file, "rb") as f:
            salt = f.read(16)
        with open(data_file, "r", encoding="utf-8") as f:
            encrypted = json.load(f)
        key = derive_key(master_password, salt)
        json_data = decrypt_data(encrypted, key)
        return json.loads(json_data)
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return {}

def save_vault(vault):
    try:
        salt = secrets.token_bytes(16) if not os.path.exists(key_file) else open(key_file, "rb").read(16)
        key = derive_key(master_password, salt)
        json_data = json.dumps(vault, ensure_ascii=False, indent=2)
        encrypted = encrypt_data(json_data, key)
        with open(data_file, "w", encoding="utf-8") as f:
            json.dump(encrypted, f, ensure_ascii=False, indent=2)
        if not os.path.exists(key_file):
            with open(key_file, "wb") as f:
                f.write(salt)
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")

# --- Генерация пароля ---
def generate_password(length=12, use_symbols=True, use_digits=True, use_upper=True):
    chars = "abcdefghjkmnpqrstuvwxyz"
    if use_upper:
        chars += "ABCDEFGHJKMNPQRSTUVWXYZ"
    if use_digits:
        chars += "23456789"
    if use_symbols:
        chars += "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

# --- Проверка утечки ---
def is_password_leaked(password: str) -> bool:
    common = ["123456", "password", "123456789", "qwerty", "admin", "123", "111111"]
    return password.lower() in common or len(password) < 6

# --- Копирование в буфер ---
def copy_to_clipboard(text):
    try:
        subprocess.run(["termux-clipboard-set"], input=text, text=True)
        print(f"✅ {safe_get('copied')}")
    except:
        print("⚠️ Буфер недоступен (установи: pkg install termux-api)")

# --- CLI ---
def show_language_popup():
    print(f"\n🌐 {safe_get('choose_language')}:")
    print("  1) 🇷🇺 Русский")
    print("  2) 🇬🇧 English")
    choice = input("\nВыберите / Choose: ").strip()
    if choice == "1":
        save_settings({"language": "ru"})
        print("✅ Язык сохранён. Перезапустите Onyx.")
    elif choice == "2":
        save_settings({"language": "en"})
        print("✅ Language saved. Restart Onyx.")
    else:
        print("❌ Неверный выбор")

def main():
    global master_password
    print(f"\n🔐 {safe_get('app_title')} — CLI")
    
    settings = load_settings()
    if "language" not in settings:
        show_language_popup()
        return

    master_password = getpass.getpass(f"\n🔐 {safe_get('enter_master')}: ").strip()
    if not master_password:
        print("❌ Пароль не может быть пустым")
        return

    vault = load_vault()
    print("✅ Доступ разрешён")

    while True:
        print("\n" + "─" * 40)
        print(f"           🏠 {safe_get('app_title')} — МЕНЮ")
        print("─" * 40)
        print(f"1) ➕ {safe_get('add_password')}")
        print(f"2) 📋 {safe_get('view_passwords')}")
        print(f"3) ⚙️ {safe_get('settings')}")
        print(f"4) 🚪 Выход")

        choice = input("\nВыберите: ").strip()

        if choice == "1":
            service = input(f"🌐 {safe_get('service')}: ").strip()
            login = input(f"🧑‍💼 {safe_get('login')}: ").strip()
            pwd = getpass.getpass(f"🔑 {safe_get('password')} (Enter — сгенерировать): ").strip()
            if not pwd:
                pwd = generate_password()
                print(f"🎲 Сгенерирован: {pwd}")
            if is_password_leaked(pwd):
                print(f"⚠️ {safe_get('weak_password')}")
            if service and login and pwd:
                vault[service] = {"login": login, "password": pwd}
                save_vault(vault)
                print("✅ Пароль сохранён")
            else:
                print("❌ Все поля обязательны")

        elif choice == "2":
            if not vault:
                print(f"📦 {safe_get('no_passwords')}")
            else:
                print("\nСохранённые пароли:")
                items = list(vault.items())
                for i, (service, data) in enumerate(items, 1):
                    print(f"  {i}) • {service} → {data['login']} | ******")

                print(f"\nВведите номер записи для управления, или Enter — назад")
                try:
                    sel = input("Выбор: ").strip()
                    if not sel:
                        continue
                    idx = int(sel) - 1
                    if 0 <= idx < len(items):
                        service, data = items[idx]
                        show_password = False
                        while True:
                            login = data['login']
                            password = data['password'] if show_password else "•" * len(data['password'])

                            print(f"\n🔐 Запись: {service}")
                            print(f"   Логин:    {login}")
                            print(f"   Пароль:   {password}")
                            print("────────────────────────")
                            if show_password:
                                print("1) 🙈 Скрыть пароль")
                            else:
                                print("1) 👁 Показать пароль")
                            print("2) 📋 Копировать логин")
                            print("3) 🔑 Копировать пароль")
                            print("4) 🗑 Удалить запись")
                            print("5) 🚪 Назад")

                            act = input("Действие: ").strip()

                            if act == "1":
                                show_password = not show_password
                            elif act == "2":
                                copy_to_clipboard(login)
                            elif act == "3":
                                copy_to_clipboard(password if show_password else data['password'])
                            elif act == "4":
                                print(f"Вы уверены, что хотите удалить '{service}'? (да/нет)")
                                confirm = input("> ").strip().lower()
                                if confirm in ("да", "yes", "y", "д"):
                                    del vault[service]
                                    save_vault(vault)
                                    print("✅ Запись удалена")
                                    break
                                else:
                                    print("❌ Удаление отменено")
                            elif act == "5":
                                break
                            else:
                                print("❌ Неверный выбор")
                    else:
                        print("❌ Нет такой записи")
                except ValueError:
                    print("❌ Введите число")

if __name__ == "__main__":
    main()


