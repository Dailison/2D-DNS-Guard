# 2D DNS Analyzer (api, coletor, classificador) — imagem do k3s (ns dns-guard, k3s/analyzer.yaml).
# Uma imagem só; o comando escolhe o serviço: api | run-collector | run-classifier | migrate.
FROM python:3.13-slim

# dig: investigação e checagem de DNS ativo (dnsativo.py, investigacao.py); tzdata: horários em America/Sao_Paulo
RUN apt-get update \
 && apt-get install -y --no-install-recommends bind9-dnsutils ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dnsanalyzer ./dnsanalyzer
COPY migrations ./migrations

RUN useradd --system --uid 10001 --home /data dnsanalyzer && install -d -o 10001 -g 10001 /data
ENV PYTHONUNBUFFERED=1 \
    TZ=America/Sao_Paulo \
    LOG_DIR= \
    DATA_DIR=/data \
    TLDEXTRACT_CACHE=/data/tldextract
USER 10001
ENTRYPOINT ["python", "-m", "dnsanalyzer"]
CMD ["api"]
