FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main_secure.py .

RUN mkdir -p /data && chown appuser:appuser /data

ENV BANK_DB=/data/bank_db.json \
    BANK_HOST=0.0.0.0 \
    BANK_PORT=9999

USER appuser

EXPOSE 9999

ENTRYPOINT ["python", "main_secure.py"]