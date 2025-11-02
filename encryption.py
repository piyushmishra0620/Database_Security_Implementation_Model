from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

FERNET_KEY = os.getenv('ENCRYPTION_KEY')
if not FERNET_KEY:
    raise RuntimeError('ENCRYPTION_KEY not found in environment. Generate with Fernet.generate_key()')

fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

STORAGE_DIR = 'encrypted_files'
os.makedirs(STORAGE_DIR, exist_ok=True)


def encrypt_bytes(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return fernet.decrypt(token)


def save_encrypted_file(filename: str, data: bytes) -> str:
    safe_path = os.path.join(STORAGE_DIR, f"{filename}.enc")
    with open(safe_path, 'wb') as f:
        f.write(encrypt_bytes(data))
    return safe_path


def read_encrypted_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return decrypt_bytes(f.read())