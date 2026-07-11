FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BACKUPRR_CONFIG=/data/config.json

WORKDIR /app

COPY pyproject.toml README.md ./
COPY backuprr ./backuprr

RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --home-dir /app backuprr \
    && mkdir -p /data /media \
    && chown -R backuprr:backuprr /data /media

USER backuprr
VOLUME ["/data", "/media"]
EXPOSE 8080

CMD ["sh", "-c", "backuprr --config \"$BACKUPRR_CONFIG\" init && backuprr --config \"$BACKUPRR_CONFIG\" web --host 0.0.0.0 --port 8080"]
