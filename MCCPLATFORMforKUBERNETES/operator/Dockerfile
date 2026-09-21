FROM registry.access.redhat.com/ubi9/python-312-minimal

USER 0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt

COPY drivers ./drivers
COPY app ./app
RUN fix-permissions /app

USER 1000:0

CMD ["python", "-m", "app.worker"]
