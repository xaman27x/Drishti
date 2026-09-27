ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY src ./src
COPY schemas ./schemas
COPY scripts ./scripts
COPY third_party ./third_party

RUN python scripts/verify_ocsf_vendor.py \
    && python scripts/verify_ocsf_bundle.py \
    && python -m pip wheel --wheel-dir /wheels ".[production]" \
    && python -m venv /opt/drishti \
    && /opt/drishti/bin/pip install --no-index --find-links=/wheels "drishti-ulpf[production]"

FROM ${PYTHON_IMAGE} AS runtime

ARG VERSION=0.0.0
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Drishti" \
      org.opencontainers.image.description="Lossless, human-governed universal log preprocessing framework" \
      org.opencontainers.image.source="https://github.com/xaman27x/Drishti" \
      org.opencontainers.image.documentation="https://github.com/xaman27x/Drishti/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

ENV DRISHTI_ENVIRONMENT=production \
    PATH="/opt/drishti/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 65532 drishti \
    && useradd --system --uid 65532 --gid drishti --home-dir /nonexistent --shell /usr/sbin/nologin drishti

COPY --from=builder /opt/drishti /opt/drishti

USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)"]

ENTRYPOINT ["uvicorn"]
CMD ["drishti.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]