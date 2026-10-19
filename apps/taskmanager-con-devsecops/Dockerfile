# Imagen endurecida: base slim con versión fija, usuario sin privilegios,
# dependencias fijadas, healthcheck y datos en volumen.
FROM python:3.14-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/database.db

RUN useradd --system --uid 10001 --no-create-home appuser \
 && mkdir /data && chown appuser /data

COPY --from=builder /install /usr/local
WORKDIR /app
COPY app.py create_db.py entrypoint.sh ./
RUN chmod 0555 entrypoint.sh

USER appuser
VOLUME /data
EXPOSE 5000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).status == 200 else 1)"

ENTRYPOINT ["./entrypoint.sh"]
