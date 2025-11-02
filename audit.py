from db_config import get_db_connection


def log_action(user_id: int, action: str, ip_address: str = None):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO db_audit_log (user_id, action, ip_address) VALUES (%s, %s, %s)",
                    (user_id, action, ip_address))
        conn.commit()
    finally:
        cur.close()
        conn.close()


def fetch_audit_logs():
    conn = get_db_connection()
    import pandas as pd
    try:
        df = pd.read_sql('SELECT * FROM db_audit_log ORDER BY timestamp DESC', conn)
        return df
    finally:
        conn.close()
        