FROM python:3.12-slim

RUN addgroup --gid 1000 app && adduser --uid 1000 --gid 1000 --disabled-password --gecos '' app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

USER 1000:1000
ENV RUNTIME_CONFIG_DIR=/config
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
