from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Создаём ключ из мастер-пароля"""
    return PBKDF2(
        master_password,
        salt,
        32,
        count=100_000,
        hmac_hash_module=SHA256
    )

def encrypt_data(data: str, master_password: str) -> dict:
    """Шифруем данные"""
    salt = get_random_bytes(16)
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return {
        'ciphertext': ciphertext.hex(),
        'salt': salt.hex(),
        'nonce': cipher.nonce.hex(),
        'tag': tag.hex()
    }

def decrypt_data(encrypted_dict: dict, master_password: str) -> str:
    """Расшифровываем"""
    try:
        salt = bytes.fromhex(encrypted_dict['salt'])
        nonce = bytes.fromhex(encrypted_dict['nonce'])
        ciphertext = bytes.fromhex(encrypted_dict['ciphertext'])
        tag = bytes.fromhex(encrypted_dict['tag'])
        key = derive_key(master_password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode('utf-8')
    except Exception:
        raise ValueError("Неверный мастер-пароль или повреждённые данные")
