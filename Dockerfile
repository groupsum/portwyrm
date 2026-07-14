FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8.4 /uv /usr/local/bin/uv

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates certbot nginx libnginx-mod-stream \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN uv pip install --system --no-cache . "psycopg[binary]>=3.2,<4" "pymysql>=1.1,<2"

COPY deploy/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /data/acme-challenge /data/nginx /data/logs /etc/letsencrypt/live /var/lib/nginx/cache/public

ENV PYTHONUNBUFFERED=1 \
    PORTWYRM_DB_BACKEND=sqlite \
    PORTWYRM_DATA_ROOT=/data \
    PORTWYRM_ADMIN_PORT=81 \
    PORTWYRM_NGINX_RUNTIME=1 \
    PORTWYRM_NGINX_ROOT=/data/nginx \
    PORTWYRM_CERTIFICATE_ROOT=/etc/letsencrypt/live \
    PORTWYRM_ACME_WEBROOT=/data/acme-challenge

VOLUME ["/data", "/etc/letsencrypt"]
EXPOSE 80 81 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:81/health/ready', timeout=3)"

ENTRYPOINT ["python", "/app/deploy/entrypoint.py"]
