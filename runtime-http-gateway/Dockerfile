FROM registry.access.redhat.com/ubi9/python-312-minimal

USER 0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY app ./app
RUN fix-permissions /app

USER 1000:0
ENV RUNTIME_CONFIG_DIR=/config
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
