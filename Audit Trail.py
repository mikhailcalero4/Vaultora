#audit trail
import sqlite3
from flask import Flask, request, g, render_template_string

app = Flask(__name__)
DATABASE = 'audit_trail.db'

def get_db():
    db = getattr(g, 'database', None)
    if db is None:
      db = g.database = sqlite3.conect(DATABASE)
      db.row_factory = sqlite3.Row
    return db
def init_db():
   with app.app_context():
      db = get_db()
      db.execute('''
                 CREATE TABLE IF NOT EXISTS audit (
                     id INTEGER KEY AUTOINCREMENT,
                     username TEXT,
                     action TEXT,
                     filename TEXT,
                     ip TEXT,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                 )'''
                 )
      db.commit()

app.teardown_appcontext
def close_connection(exception):
   db = getattr(g, '_database', None)
   if db:
      db.close()

#log an action
def log_action(username, action, filename):
   ip = request.remote_addr
   db = get_db()
   db.execute('INSERT INTO audit (username, action, filename, ip) VALUES (?, ?, ?, ?))',
               (username, action, filename, ip))
   db.commit()

#example usage in a file upload route
@app.route('/upload', methods=['POST'])
def upload():
   #file upload code here
   username = request.form.get('username', 'unknown') #example: adjust your auth
   filename = request.files['file'].filename
   #save file logic...
   log_action(username, 'upload', filename)
   return 'File uploaded and audit logged'

#admin view: searchable audit trail
@app.route('/audit')
def audit_view():
   username = request.args.get('username')
   action = request.args.get('action')
   filename = request.args.get('filename')

   query = 'SELECT * FROM audit WHERE 1=1'
   params = []

   if username:
      query += " AND username LIKE ?"
      params.append(f"%{username}%")
      if action:
         query += " AND action LIKE ?"
         params.append(f"%{action}%")
         if filename:
            query += " AND filename LIKE ?"
            params.append(f"%{filename}%")

            db = get_db()
            cur = db.execute(query, params)
            records = cur.fetchall()

html = """
<h2>Audit Trail</h2>
<form method="get">
    Usename: <input name="username" value="{{request.args.get'username', ''}}">
    Action: <input name="action value="{{request.args.get('action', '')}}">
    Filename: <input name="filename" value="{{request.args.get('filename', '')}}">
    <button type = "submit">Search</button>
</form>
<table border="1" cellpadding="5" cellspacing="0">
   <tr><th>ID</th>Username</th><th>Action</th><th>Filename</th><th?IP</th><th>Timestamp</th><tr>
   {5 for row in records %}
   <tr>
      <td>{{ row['id'] }}</td>
      <td>{{ row['username'] }}</td>
      <td>{{ row['action'] }}</td>
      <td>{{ row['filename'] }}</td>
      <td>{{ row['ip] }}</td>
      <td>{{ row['timestamp'] }}</td>
    <tr>
    {% endfor %}
</table>
"""
return render_template_string(html, records=records)

if __name__ == '__main__':
   init_db()
   app.run(debug=True)