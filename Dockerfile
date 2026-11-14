FROM python:3.13-alpine

RUN apk add --no-cache tzdata && adduser -D -H -u 10001 app
WORKDIR /app
COPY app.py /app/app.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8080

USER app
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "-I", "/app/app.py"]
