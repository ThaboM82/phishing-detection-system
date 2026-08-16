FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Added timeout and retries to handle poor connectivity
RUN pip install --no-cache-dir --default-timeout=1000 --retries 10 --upgrade pip

COPY requirements.txt .

# Added timeout and retries for package downloads
RUN pip install --no-cache-dir --default-timeout=1000 --retries 10 -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]