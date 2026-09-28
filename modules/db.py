import sqlite3
from pathlib import Path
from datetime import datetime
import pandas as pd

def init_db(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT,
            sender TEXT,
            text_preview TEXT,
            prediction TEXT,
            risk_score REAL,
            risk_level TEXT,
            indicators TEXT
        )
        """)
        conn.commit()

def add_analysis(path, source, sender, text, prediction, risk_score, risk_level, indicators):
    with sqlite3.connect(path) as conn:
        conn.execute("""
        INSERT INTO analyses(created_at,source,sender,text_preview,prediction,risk_score,risk_level,indicators)
        VALUES(?,?,?,?,?,?,?,?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            source, sender, (text or "")[:180], prediction, risk_score, risk_level,
            ", ".join(indicators or [])
        ))
        conn.commit()

def load_history(path):
    with sqlite3.connect(path) as conn:
        return pd.read_sql_query("SELECT * FROM analyses ORDER BY id DESC", conn)

def clear_history(path):
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM analyses")
        conn.commit()
