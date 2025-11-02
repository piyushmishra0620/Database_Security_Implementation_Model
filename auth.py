import bcrypt
from db_config import get_db_connection

def hash_password(plain: str) -> bytes:
    return bcrypt.hashpw(plain.encode('utf-8'), bcrypt.gensalt())


def check_password(plain: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(plain.encode('utf-8'), hashed)


def register_user(username: str, password: str, role: str = 'user') -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    pw_hash = hash_password(password)
    try:
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                    (username, pw_hash.decode('utf-8'), role))
        conn.commit()
        user_id = cur.lastrowid
    finally:
        cur.close()
        conn.close()
    return user_id


def authenticate_user(username: str, password: str):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash, role FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        if not row:
            return None
        user_id, password_hash, role = row
        if check_password(password, password_hash.encode('utf-8')):
            return {'id': user_id, 'username': username, 'role': role}
        return None
    finally:
        cur.close()
        conn.close()