"""database.py - SQLite storage for the history of checked messages."""
import json
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scam_spotter.db")


def get_connection(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path=None):
    """Create the table if it does not exist."""
    with get_connection(path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )""")


def save_check(message, score, level, indicators, path=None):
    with get_connection(path) as conn:
        conn.execute(
            "INSERT INTO checks (message, score, risk_level, indicators) VALUES (?,?,?,?)",
            (message, score, level, json.dumps(indicators)))


def get_history(limit=20, path=None):
    with get_connection(path) as conn:
        rows = conn.execute(
            "SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    history = []
    for r in rows:
        item = dict(r)
        item["indicators"] = [i["description"] for i in json.loads(item["indicators"] or "[]")]
        history.append(item)
    return history


def clear_history(path=None):
    with get_connection(path) as conn:
        conn.execute("DELETE FROM checks")
