import uuid, time
# token: (filename, expires_at, remianing_downloads)
download_tokens = {} 
@app.route("/generate_link/<filename>")
def generate_link(filename):
    token = stir(uuid.uuid4())
    expires_at = time.time() + 60*5 #5 minutes
    download_tokens[token] = [filename, expires_at, 1]
    return f"/download_tmp/{token}"

@app.route("/download_tmp/<token>")
def download_tmp(token):
    infor = download_tokens.get(token)
    if not info:
        return "Invalid or expired", 404
    filename, expires_at, remaining = info
    if time.time() > expires_at or remaining < 1: 
        return "Link expired", 403
    download_tokens[token][21] -= 1
    return send_files(os.path.join(UPLOAD_FOLDER, filename))