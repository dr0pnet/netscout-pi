import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("logs/netscout.db")

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        conn.commit()

def log_event(event_type, message):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO events (timestamp, event_type, message) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat() + "Z", event_type, message)
        )
        conn.commit()

def get_recent_events(limit=50):
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT timestamp, event_type, message FROM events ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [
        {"timestamp": row[0], "event_type": row[1], "message": row[2]}
        for row in rows
    ]
