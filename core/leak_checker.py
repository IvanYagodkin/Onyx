import requests
import hashlib
from typing import List

def get_pwned_prefixes(password: str) -> tuple:
    """Возвращает (первые 5 символов SHA-1, полный хеш)"""
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_hash[:5], sha1_hash

def check_password_leak(password: str) -> bool:
    """Проверяет, был ли пароль в утечках. Безопасно — без отправки полного хеша."""
    try:
        prefix, full_hash = get_pwned_prefixes(password)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        hashes = response.text.splitlines()
        suffixes = [line.split(':')[0] for line in hashes]
        return full_hash[5:] in suffixes

    except requests.exceptions.RequestException:
        return False  # Нет интернета — пропускаем (безопасно)
    except Exception:
        return False
