#file expiration/retention
import os 
import sqlite3
import time
from flask import Flask, request, jsonify, g

app = Flask (__name__)
UPLOAD_FOLDER = "uploads"
DB_FILE = "retention.db"
if not os.path.exists(UPLOAD_FOLDER):
    os.makeddirs(UPLOAD_FOLDER)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_FILE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
                   CREATE TABLE IF NOT EXISTS files (
                      id INTEGER PRIMARY KEY,
                      filename TEXT,
                      expiry_at INTEGER -- store as unix timestamp (seconds)
                   )
                ''')
        db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db:
        db.close()