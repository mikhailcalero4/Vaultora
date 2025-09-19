import os
import shutil
import datetime
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
VERSIONS_FOLDER = "versions" #store older versions here
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(VERSIONS_FOLDER):
    os.makedirs(VERSIONS_FOLDER)

def save_version(filename):
    original_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(original_path):
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        versioned_name = f"{filename}.{timestamp}"
        versioned_path = os.path.join(VERSIONS_FOLDER, versioned_name)
        shutil.copyfile(original_path, versioned_path)
        print(f"Saved version as {versioned_name}")

@app.route("/upload", methods=["POST"])
def upload():
    file = request.file["file"]
    filename = file.filename

    #save existing file version before overwriting
    save_version(filename)

    #save new file
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    return jsonify({"message": f"File '{filename}' uploaded with version saved."})

@app.route("/versions/<filename>")
def versions(filename):
    #list all versions available for a file
    versions = []
    for f in os.listdir(VERSIONS_FOLDER):
        if f.startswith(filename + "."):
            versions.append(f)
    versions.sort(reverse=True)
    return jsonify({"versions": versions})
@app.route("/rollback/<versioned_filename>")
def rollback(versioned_filename):
    versioned_path = os.path.join(VERSIONS_FOLDER, versioned_filename)
    if not os.path.exists(versioned_path):
        return jsonify({"message": "Version not found"}), 404

     #copy selected version back to uploads folder (rollback
    original_name = versioned_filename.split(".")[0]
    rollback_path = os.path.join(UPLOADED_FOLDER, original_name)
    shutil.copyfile(versioned_path, rollback_path)
    return jsonify({"message": f"Rolled back to version {versioned_filename}"})

@app.route("/")
def index():
    files = os.listdir(UPLOADED_FOLDER)
    return jsonify({"files": files})