FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
RUN groupadd -r -g 1000 app && useradd -r -u 1000 -g app -d /app -s /bin/bash app && chown -R app:app /app
USER app
ENV MODEL_DIR=/app/models PYTHONPATH=/app/src
EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
