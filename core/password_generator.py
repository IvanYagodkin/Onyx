import random
import string

def generate_password(
    length: int = 12,
    use_digits: bool = True,
    use_symbols: bool = True,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """Генерирует надёжный пароль"""
    chars = ""
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*"

    if exclude_ambiguous:
        for char in "0O1lI":
            chars = chars.replace(char, "")

    if not chars:
        raise ValueError("Нет символов для генерации")

    while True:
        password = ''.join(random.choice(chars) for _ in range(length))
        # Проверим, что пароль соответствует требованиям
        if use_digits and not any(c.isdigit() for c in password):
            continue
        if use_symbols and not any(c in "!@#$%^&*" for c in password):
            continue
        if use_uppercase and not any(c.isupper() for c in password):
            continue
        if use_lowercase and not any(c.islower() for c in password):
            continue
        return password
