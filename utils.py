import re


def validate_username(username: str) -> bool:
    return bool(re.match(r'^[A-Za-z0-9_.-]{3,48}$', username))


def validate_password_strength(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True