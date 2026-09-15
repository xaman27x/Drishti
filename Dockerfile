FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system drishti && useradd --system --gid drishti drishti

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY schemas ./schemas
COPY scripts ./scripts
COPY third_party ./third_party
RUN python scripts/verify_ocsf_vendor.py \
    && python scripts/verify_ocsf_bundle.py
RUN python -m pip install ".[production]"

USER drishti
EXPOSE 8080

CMD ["uvicorn", "drishti.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
