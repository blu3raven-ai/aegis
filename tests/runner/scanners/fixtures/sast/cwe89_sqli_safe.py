import sqlite3
from flask import request

def search():
    db = sqlite3.connect("app.db")
    user_id = request.args.get("id")
    rows = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return {"rows": rows}
