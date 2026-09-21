FROM registry.access.redhat.com/ubi9/python-312-minimal

ARG OPENSHIFT_CLIENT_URL=https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/openshift-client-linux.tar.gz

USER 0

# curl jest już w obrazie jako curl-minimal (HTTP/HTTPS). Instalacja pełnego
# pakietu `curl` wywołałaby konflikt z curl-minimal.
# iputils = ping, openssh-clients = ssh, shadow-utils = useradd.
RUN microdnf install -y --nodocs --setopt=install_weak_deps=0 \
        ca-certificates gzip tar jq iputils openssh-clients shadow-utils \
    && microdnf clean all \
    && curl -fsSL "$OPENSHIFT_CLIENT_URL" -o /tmp/openshift-client.tar.gz \
    && tar -xzf /tmp/openshift-client.tar.gz -C /usr/local/bin oc kubectl \
    && chmod 0755 /usr/local/bin/oc /usr/local/bin/kubectl \
    && rm -f /tmp/openshift-client.tar.gz

# Wpis w /etc/passwd jest potrzebny klientowi ssh — bez niego odmawia
# działania komunikatem "No user exists for uid".
RUN useradd -u 1000 -g 0 -m runtime

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY app ./app
RUN fix-permissions /app

USER 1000:0
ENV RUNTIME_CONFIG_DIR=/config
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
