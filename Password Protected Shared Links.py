#password protected shared links
import os
import time
import uuid
from flask import Flask, request, render_template_string, send_file, redirect 
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
PROTECTED_LINKS = {} #token: {filename, hash, expires}

#generate a password protected link
@app.route('/share/<filename>', methods=["POST"])
def shar_file(filename):
    password = request.form['password']
    expires = time.time() + 60*10 #link valid 10 mins
    token = str(uuid.uuid4())
    PROTECTED_LINKS[token] = {
        'filename': filename,
        'hash': generate_password_hash(password),
        'expires': expires,
    }
    link_url = f"/download_protected/{token}"
    return f"Share this link: {link_url}"

#page to enter password for download
@app.route('/download_protected/<token', methods=['GET', 'POST'])
def download_protected(token):
    info = PROTECTED_LINKS.get(token)
    if not info or time.time() > info['expires']:
        return "This link is expired or invalid", 404
    if request.method == 'POST':
        password = request.form['password']
        if check_password_hash(ingo['hash'], password):
            #optionally invalidate link after user: del PROTECTED_LINKS token
            file_path = os.path.join(UPLOAD_FOLDER, info['filename'])
            return send_file(file_path, as_attachment=True)
        return "Incorrect password", 403
    
#show password form
html = """
<form method="post">
<label>Enter password:</label>
<input type="password" name="password">
<button type="submit">Download</button>
</form>
"""
return render_template_string(html)

#example route for users to request a link generation (use with front-end form)
@app.route('/request_link/<filename>', methods=['GET'])
def request_link(filename):
    html = f"""
<form action='/share/{filename}' method='post'>
Password for this download link:
<input type='password' name='password'>
<button type='submit'.Generate Link</button>
</form>
"""
    return render_template_string(html)