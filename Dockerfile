FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed for pyclamd and cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Create runtime folders
RUN mkdir -p uploads versions backups sensitive_files

# Don't run as root — create a dedicated user
RUN useradd -m vaultora && chown -R vaultora /app
USER vaultora

EXPOSE 8000

ENV FLASK_DEBUG=false

CMD ["python", "serve.py"]