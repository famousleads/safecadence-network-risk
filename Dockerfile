# SafeCadence NetRisk — Docker image (v11.2)
#
# Python 3.12-slim runtime. Multi-stage build keeps the final image small
# while ensuring native deps (cryptography, bcrypt) can compile in the
# builder stage.
#
# Usage:
#   docker build -t famousleads/safecadence-netrisk:11.2.0 .
#   docker run -p 8003:8003 -v sc-data:/data famousleads/safecadence-netrisk:11.2.0
#
# Or use docker-compose.yml to bring up the full local dev stack.

# ---------------- Builder stage ----------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libffi-dev libssl-dev build-essential cargo && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src ./src

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir '.[server,ssh,vault,ai]'

# ---------------- Runtime stage ----------------
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/famousleads/safecadence-network-risk"
LABEL org.opencontainers.image.description="SafeCadence NetRisk — local-first multi-vendor infrastructure platform."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="SafeCadence NetRisk"
LABEL org.opencontainers.image.version="11.2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
      libffi8 libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r safecadence && useradd -r -g safecadence safecadence && \
    mkdir -p /data && chown safecadence:safecadence /data

COPY --from=builder /opt/venv /opt/venv

VOLUME ["/data"]
WORKDIR /work

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAFECADENCE_DATA_DIR=/data \
    SC_DATA_DIR=/data

USER safecadence

EXPOSE 8003

ENTRYPOINT ["safecadence"]
CMD ["ui", "--host", "0.0.0.0", "--port", "8003"]
