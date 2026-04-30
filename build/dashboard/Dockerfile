FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN groupadd -r -g 1000 app && useradd -r -u 1000 -g app -d /app -s /bin/bash app \
    && chown -R app:app /app

USER app
EXPOSE 8501

CMD ["streamlit", "run", "src/app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
