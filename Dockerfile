# SafeCadence Device Intelligence Platform — Docker image
#
# Multi-stage build: install deps in builder, copy minimal artifacts to slim runtime.
# Final image is ~80MB on Alpine, supports linux/amd64 + linux/arm64.
#
# Usage:
#   # Local UI (Audit + Platform + Policy tabs) on port 8765
#   docker run -p 8765:8765 -v sc-data:/data fkarim1/netrisk ui --host 0.0.0.0
#
#   # CLI one-offs
#   docker run --rm fkarim1/netrisk policy templates
#   docker run --rm -v $(pwd):/work fkarim1/netrisk scan /work/router.txt --json /work/out.json
#   docker run --rm fkarim1/netrisk discover 192.168.4.0/24
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t fkarim1/netrisk:6.1.0 -t fkarim1/netrisk:latest --push .

# ---------------- Builder stage ----------------
FROM python:3.12-alpine AS builder

WORKDIR /build

# Build dependencies for any compiled extensions (cryptography, bcrypt, etc.)
RUN apk add --no-cache \
    gcc musl-dev libffi-dev openssl-dev cargo make

COPY pyproject.toml README.md LICENSE CHANGELOG.md ./
COPY src ./src

# Install with all extras into a virtualenv we'll copy to the runtime stage
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir '.[server,ssh,vault,ai]'

# ---------------- Runtime stage ----------------
FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/famousleads/safecadence-network-risk"
LABEL org.opencontainers.image.description="Free, open-source infrastructure platform — 40 vendor adapters across 6 domains, AI policy intelligence engine, multi-vendor remediation. Local-first, BYO-AI, never executes."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="SafeCadence Device Intelligence Platform"
LABEL org.opencontainers.image.version="6.1.0"

# Minimal runtime deps — libssl/libffi for cryptography, ca-certificates for TLS
RUN apk add --no-cache libffi openssl ca-certificates && \
    addgroup -S safecadence && adduser -S safecadence -G safecadence

COPY --from=builder /opt/venv /opt/venv

# Make scan/discover output writable to a known volume
VOLUME ["/data"]
WORKDIR /work

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SAFECADENCE_DATA_DIR=/data

USER safecadence

EXPOSE 8765

ENTRYPOINT ["safecadence"]
CMD ["--help"]
