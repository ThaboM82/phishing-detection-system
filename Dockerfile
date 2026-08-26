# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a wheel store or site-packages
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: Production Runtime ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source code and ML pipeline artifacts
COPY src/ ./src/
COPY models/ ./models/
# Copy model pickle file if stored in root directory
COPY phishing_rf_model.pkl ./phishing_rf_model.pkl 

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Expose FastAPI port
EXPOSE 8000

# Non-root user safety configuration
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Launch via Uvicorn (Single worker for predictable ML memory management, or adjust workers)
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]