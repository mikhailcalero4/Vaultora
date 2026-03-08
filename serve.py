from waitress import serve
from app import create_app

app = create_app()

if __name__ == "__main__":
    print("🔒 Vaultora running at http://127.0.0.1:8000")
    serve(app, host="0.0.0.0", port=8000)