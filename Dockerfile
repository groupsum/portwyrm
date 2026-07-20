FROM python:3.12-slim

ARG OCI_REVISION=unknown
ARG OCI_VERSION=dev
ARG OCI_SOURCE=https://github.com/groupsum/portwyrm
ARG OCI_CREATED=unknown

LABEL org.opencontainers.image.title="Portwyrm" \
      org.opencontainers.image.description="Nginx Proxy Manager compatible control and data plane" \
      org.opencontainers.image.source="${OCI_SOURCE}" \
      org.opencontainers.image.revision="${OCI_REVISION}" \
      org.opencontainers.image.version="${OCI_VERSION}" \
      org.opencontainers.image.created="${OCI_CREATED}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=ghcr.io/astral-sh/uv:0.8.4 /uv /usr/local/bin/uv

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates certbot nginx libnginx-mod-stream \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN uv pip install --system --no-cache "pip==26.1.2" .

COPY deploy/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /data/acme-challenge /data/nginx /data/logs /etc/letsencrypt/live /var/lib/nginx/cache/public

ENV PYTHONUNBUFFERED=1 \
    PORTWYRM_DB_BACKEND=sqlite \
    PORTWYRM_DATA_ROOT=/data \
    PORTWYRM_ADMIN_PORT=81 \
    PORTWYRM_NGINX_RUNTIME=1 \
    PORTWYRM_NGINX_RELOAD=1 \
    PORTWYRM_HOST_PROBES=1 \
    PORTWYRM_NGINX_ROOT=/data/nginx \
    PORTWYRM_CERTIFICATE_ROOT=/etc/letsencrypt/live \
    PORTWYRM_ACME_WEBROOT=/data/acme-challenge \
    PORTWYRM_AUTO_BOOTSTRAP_ADMIN=1 \
    PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE=/data/bootstrap-admin.json \
    PORTWYRM_SECURE_COOKIES=1

VOLUME ["/data", "/etc/letsencrypt"]
EXPOSE 80 81 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:81/health/ready', timeout=3)"

ENTRYPOINT ["python", "/app/deploy/entrypoint.py"]
