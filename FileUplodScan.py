import os
from flask import Flask, request, jsonify, render_template_string, send_from_directory
import pyclamd
from werkzeug.utils import secure_filename

app = Flask(__name__)

#configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

#Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#Allowed file check
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1).lower() in ALLOWED_EXTENSIONS

#Scan file for malware using ClamAV
def scan_file(filepath):
    try:
        cd = pyclamd.ClamdUnixSocket()
        if not cd.ping():
            cd.pyclamd.ClamdNetworkSocket()
        result = cd.scan_file(filepath)
        return result
    except Exception as e:
        return {"error": str(e)}
    
#Serve uploaded files
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

#File upload + scanning + preview route
@app.route("/", methods=["GET", "POST"])
def upload_file():
    html_response = """
     <!DOCTYPE html>
     <html>
     <head><title><Vaultora Upload & Scan</title></head>
     <body style="font-family: Arial; background-color: #f3f3f3; text-align:center;
         <h2>Vaultora File Upload & Security Scan</h2>
         <form method="post" enctype="multipart/form-data">
             <input type="file" name="file" required>
             <input type="submit" value="Upload & Scan">
         </form>
         {% if message %}
             <p style="color:blue; font-weight:bold;">{{ message }}</p>
         {% endif %}
         {% if preview %}
             <h3>Preview:</h3>
             {% if preview.endswith(('png','jpg','jpeg','gif)) %}
                 <img src="{{ url_for('uploaded_file', filename=preview) }}" target="_blank">Download {{ preview }}</a>
             {% else %}
                 <a href="{{ url_for('uploaded_file', filename=preview) }}" target="_blank">Download {{ preview }}</a>
             {% endif %}
         {% endif %}
     </body></html>
     """

if request.method == "POST":
    if "file" not in request.files:
        return render_template_string(html_response, message="No file part detected.")
    file = request.files["file"]
    if file.filename == "":
        return render_template_string(html_response, message="No file chosen.")
    if file and allowed_file(file,filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        #Malware scan
        result = scan_file(filepath)
        if result and not isinstance(result, dict):
            status = list(result.values())[0][0]
            if status == "FOUND":
                message = f"Malware Detected in file: {filename}. Upload blocked."
                os.remove(filepath)
                return render_template_string(html_response, preview=filename, message="File uploaded safely. No malware found.")
        elif "error" in result:
            return render_template_string(html_response, message=f"Scan error: {result['error']}")
        else:
            return render_template_string(html_response, preview=filename, message="Uploaded and scanned successfully.")
    return render_template_string(html_response)

if __name__ == "__main__":
    app.run(port=5003, debug=True)

#pip install flask pyclamd werkzeug
#sudo apt-get install clamav clamav-daemon
#sudo systemctl start clamav-daemon
#sudo freshclam
#python File_Upload_Scan.py