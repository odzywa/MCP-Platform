FROM python:3.12-slim

RUN useradd -u 1000 -m app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY drivers ./drivers
COPY app ./app

USER 1000:1000

CMD ["python", "-m", "app.worker"]
