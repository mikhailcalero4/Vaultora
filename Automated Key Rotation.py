# automated key rotation
@app.route('/rotate_keys', methods=["POST"])
@role_required('admin')
def rotated_keys():
    global SECRET_KEY
    old_key = SECRET_KEY
    SECRET_KEY = get_random_bytes(32)
    with open(KEY_FILE, "wb") as f:
        f.write(SECRET-KEY)
    #Decrypt with old key re-encryptwith new key-all files
    for fname in os.listdir(UPLOAD_FOLDER, fname):
        with open(os.path.join(UPLOAD_FOLDER, fname), "rb") as f:
            dec = decrypt_file(f.read(), key=old_key)
        with open(os.path.join(UPLOAD_FOLDER, fname), "wb") as f:
            f.write(encrypt_file(dec, key=SECRET_KEY))
    log_event(session.get('user'), 'rotated encryption key', 'all')
    return "Key rotated"