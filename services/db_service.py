import sqlite3

DB_PATH = "osa.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    with open("database/schema.sql") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
