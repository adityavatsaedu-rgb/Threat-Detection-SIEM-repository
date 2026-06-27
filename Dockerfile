FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

LABEL org.opencontainers.image.title="Threat Detection SIEM Engine"
LABEL org.opencontainers.image.description="Production-grade Sigma threat detection"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/adityavatsaedu-rgb/Threat-Detection-SIEM-repository"

RUN groupadd -r siem && useradd -r -g siem -s /sbin/nologin siem

WORKDIR /app

COPY --from=builder /install /usr/local
COPY detectors/   ./detectors/
COPY parsers/     ./parsers/
COPY enrichment/  ./enrichment/
COPY alerting/    ./alerting/
COPY correlations/ ./correlations/
COPY rules/       ./rules/
COPY config/      ./config/
COPY scripts/     ./scripts/

RUN chown -R siem:siem /app
USER siem

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO

ENTRYPOINT ["python", "-m", "detectors.sigma_engine"]
CMD ["--mode", "realtime", "--rules", "/app/rules/sigma"]
