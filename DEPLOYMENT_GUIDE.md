# AutoSecDev Deployment Guide

## Overview

The AutoSecDev application is a Streamlit-based security analysis pipeline that can be deployed in multiple ways.

---

## Local Development

### Prerequisites
```bash
python 3.8+
pip
git
```

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd autosecdev
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Download models** (optional, for local models mode)
```bash
python download_models.py
```

5. **Configure settings**
```bash
cp .env.example .env
# Edit .env with your settings
```

6. **Run the app**
```bash
streamlit run app.py
```

The app will be available at `http://localhost:8501`

---

## Deployment Options

### Option 1: Streamlit Cloud (Recommended for Streamlit apps)

**Pros**: Easy, free tier available, automatic updates
**Cons**: Limited resources, public by default

**Steps**:
1. Push code to GitHub
2. Go to https://streamlit.io/cloud
3. Click "New app"
4. Select repository and branch
5. Set main file path: `app.py`
6. Deploy

**Configuration**:
Create `.streamlit/secrets.toml`:
```toml
llm_provider = "ollama"
ollama_url = "http://localhost:11434"
ollama_model = "codellama:7b"
```

---

### Option 2: Docker Deployment

**Pros**: Consistent environment, easy scaling
**Cons**: Requires Docker knowledge

**Dockerfile**:
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

**Build and run**:
```bash
# Build image
docker build -t autosecdev:latest .

# Run container
docker run -p 8501:8501 \
  -e LLM_PROVIDER=ollama \
  -e OLLAMA_URL=http://host.docker.internal:11434 \
  autosecdev:latest
```

**Docker Compose**:
```yaml
version: '3.8'

services:
  autosecdev:
    build: .
    ports:
      - "8501:8501"
    environment:
      - LLM_PROVIDER=ollama
      - OLLAMA_URL=http://ollama:11434
    depends_on:
      - ollama
    volumes:
      - ./Models:/app/Models

  ollama:
    image: ollama/ollama:latest
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    command: serve

volumes:
  ollama_data:
```

---

### Option 3: Heroku Deployment

**Pros**: Simple, good for small apps
**Cons**: Paid tier required, limited resources

**Procfile**:
```
web: streamlit run app.py --server.port=$PORT --server.address=0.0.0.0
```

**Deploy**:
```bash
# Install Heroku CLI
# Login
heroku login

# Create app
heroku create autosecdev

# Set environment variables
heroku config:set LLM_PROVIDER=openrouter
heroku config:set OPENROUTER_API_KEY=your_key

# Deploy
git push heroku main
```

---

### Option 4: AWS Deployment

#### Option 4a: AWS App Runner (Easiest)

**Steps**:
1. Push code to GitHub
2. Go to AWS App Runner
3. Create service from GitHub repository
4. Configure:
   - Runtime: Python 3.10
   - Build command: `pip install -r requirements.txt`
   - Start command: `streamlit run app.py --server.port=8080 --server.address=0.0.0.0`
5. Set environment variables
6. Deploy

#### Option 4b: AWS EC2

**Steps**:
1. Launch EC2 instance (Ubuntu 20.04+)
2. SSH into instance
3. Install dependencies:
```bash
sudo apt-get update
sudo apt-get install -y python3-pip git

# Clone repo
git clone <repo-url>
cd autosecdev

# Install Python packages
pip3 install -r requirements.txt

# Run with systemd
sudo nano /etc/systemd/system/autosecdev.service
```

**Service file**:
```ini
[Unit]
Description=AutoSecDev Streamlit App
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/autosecdev
ExecStart=/usr/bin/python3 -m streamlit run app.py --server.port=8501 --server.address=0.0.0.0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start**:
```bash
sudo systemctl enable autosecdev
sudo systemctl start autosecdev
```

---

### Option 5: Google Cloud Run

**Pros**: Serverless, pay-per-use, good for variable load
**Cons**: Cold starts, limited execution time

**Steps**:
1. Create `cloudbuild.yaml`:
```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/autosecdev', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/autosecdev']
  - name: 'gcr.io/cloud-builders/run'
    args:
      - 'deploy'
      - 'autosecdev'
      - '--image=gcr.io/$PROJECT_ID/autosecdev'
      - '--platform=managed'
      - '--region=us-central1'
      - '--port=8080'
      - '--memory=2Gi'
      - '--timeout=3600'
```

2. Deploy:
```bash
gcloud builds submit --config cloudbuild.yaml
```

---

## Environment Configuration

### Environment Variables

```bash
# LLM Configuration
LLM_PROVIDER=ollama|openrouter|anthropic
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama:7b
OPENROUTER_API_KEY=your_key
ANTHROPIC_API_KEY=your_key

# Model Configuration
MODEL_CACHE_DIR=/path/to/models
USE_GPU=true|false

# Server Configuration
SERVER_PORT=8501
SERVER_ADDRESS=0.0.0.0
SERVER_HEADLESS=true
```

### .env File Example

```bash
# LLM Provider
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=codellama:7b

# Model paths
DETECTION_MODEL_PATH=Models/DetectionModel/codebert_lora_finetuned
PATCHING_MODEL_PATH=Models/PatchingModel/codet5_lora_finetuned

# Performance
USE_GPU=true
MAX_WORKERS=4

# Logging
LOG_LEVEL=INFO
```

---

## Performance Optimization

### For Production

1. **Use GPU**:
```bash
export CUDA_VISIBLE_DEVICES=0
```

2. **Increase workers**:
```bash
streamlit run app.py --logger.level=warning --client.showErrorDetails=false
```

3. **Cache models**:
```bash
export HF_HOME=/path/to/cache
```

4. **Use reverse proxy** (Nginx):
```nginx
upstream streamlit {
    server localhost:8501;
}

server {
    listen 80;
    server_name autosecdev.example.com;

    location / {
        proxy_pass http://streamlit;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

---

## Monitoring & Logging

### Streamlit Logging

```python
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Log to file
handler = logging.FileHandler('autosecdev.log')
logger.addHandler(handler)

logger.info("Pipeline started")
```

### Health Checks

```bash
# Check if app is running
curl http://localhost:8501/_stcore/health

# Check specific endpoint
curl http://localhost:8501/
```

### Monitoring Tools

- **Prometheus**: Metrics collection
- **Grafana**: Visualization
- **ELK Stack**: Log aggregation
- **Sentry**: Error tracking

---

## Troubleshooting

### Issue: "app" not found

**Solution**: Ensure `app.py` exports `app` or `application`:
```python
def application(environ, start_response):
    # WSGI app
    pass

app = application
```

### Issue: Models not loading

**Solution**: 
1. Check model paths
2. Verify disk space
3. Check internet connection
4. Clear cache: `rm -rf ~/.cache/huggingface/hub/`

### Issue: Out of memory

**Solution**:
1. Use smaller batch sizes
2. Enable GPU
3. Reduce max_length
4. Use model quantization

### Issue: Slow inference

**Solution**:
1. Enable GPU
2. Use batch processing
3. Cache models
4. Use smaller models

---

## Security Considerations

### For Production Deployment

1. **Use HTTPS**:
```bash
streamlit run app.py --server.sslCertFile=cert.pem --server.sslKeyFile=key.pem
```

2. **Authentication**:
```python
import streamlit as st

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    password = st.text_input("Password", type="password")
    if password == "your_password":
        st.session_state.authenticated = True
    else:
        st.stop()
```

3. **Rate limiting**:
```python
from datetime import datetime, timedelta

if 'last_request' not in st.session_state:
    st.session_state.last_request = datetime.now()

if datetime.now() - st.session_state.last_request < timedelta(seconds=1):
    st.error("Rate limit exceeded")
    st.stop()

st.session_state.last_request = datetime.now()
```

4. **Input validation**:
```python
import re

def validate_code(code):
    if len(code) > 100000:
        raise ValueError("Code too large")
    if not re.match(r'^[a-zA-Z0-9\s\n\(\)\{\}\[\]\.\,\;\:\=\+\-\*\/\%\&\|\^\!\~\<\>\?]+$', code):
        raise ValueError("Invalid characters")
    return True
```

---

## Scaling

### Horizontal Scaling

Use load balancer with multiple instances:
```yaml
# Docker Compose with load balancer
version: '3.8'

services:
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - app1
      - app2

  app1:
    build: .
    environment:
      - INSTANCE_ID=1

  app2:
    build: .
    environment:
      - INSTANCE_ID=2
```

### Vertical Scaling

Increase resources:
- More CPU cores
- More RAM
- GPU acceleration
- Faster storage

---

## Backup & Recovery

### Backup Strategy

```bash
# Backup models
tar -czf models_backup.tar.gz Models/

# Backup configuration
tar -czf config_backup.tar.gz .env .streamlit/

# Backup logs
tar -czf logs_backup.tar.gz *.log
```

### Recovery

```bash
# Restore models
tar -xzf models_backup.tar.gz

# Restore configuration
tar -xzf config_backup.tar.gz

# Restart service
systemctl restart autosecdev
```

---

## Support & Resources

- **Streamlit Docs**: https://docs.streamlit.io
- **GitHub Issues**: https://github.com/streamlit/streamlit/issues
- **Community Forum**: https://discuss.streamlit.io
- **AutoSecDev Docs**: See IMPLEMENTATION_COMPLETE.md

---

## Quick Start Commands

```bash
# Local development
streamlit run app.py

# Docker
docker build -t autosecdev . && docker run -p 8501:8501 autosecdev

# Production (with Gunicorn)
gunicorn --bind 0.0.0.0:8000 app:application

# With environment file
export $(cat .env | xargs) && streamlit run app.py
```

---

**Last Updated**: May 2026
**Version**: 1.0.0
