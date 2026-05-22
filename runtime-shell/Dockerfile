FROM python:3.12-slim

ARG OPENSHIFT_CLIENT_URL=https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/openshift-client-linux.tar.gz

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gzip iputils-ping jq openssh-client tar \
    && curl -fsSL "$OPENSHIFT_CLIENT_URL" -o /tmp/openshift-client.tar.gz \
    && tar -xzf /tmp/openshift-client.tar.gz -C /usr/local/bin oc kubectl \
    && chmod 0755 /usr/local/bin/oc /usr/local/bin/kubectl \
    && rm -rf /var/lib/apt/lists/* /tmp/openshift-client.tar.gz

RUN useradd -u 1000 -m runtime
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
USER 1000:1000
ENV RUNTIME_CONFIG_DIR=/config
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
