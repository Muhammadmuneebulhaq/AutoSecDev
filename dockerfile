FROM python:3.10-slim

WORKDIR /app

# Install minimal system dependencies (no GPU, just static analysis tools)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies (lightweight - no torch/transformers for local models)
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code only (no Models/, data/, notebooks/)
COPY app.py .
COPY autosecdev/ ./autosecdev/

# Set environment variables for API-only mode
ENV AUTOSECDEV_LLM_PROVIDER=openrouter
ENV PYTHONUNBUFFERED=1

# Expose API port
EXPOSE 8000

# Health check for API server
HEALTHCHECK CMD curl --fail http://localhost:8000/healthz || exit 1

# Run FastAPI server (API-only, no local models)
CMD ["uvicorn", "autosecdev.api.server:app", "--host", "0.0.0.0", "--port", "8000"]