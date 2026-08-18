FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/opt/huggingface \
    PORT=8082

WORKDIR /app

RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev
RUN uv run --no-sync python -c "from huggingface_hub import snapshot_download; snapshot_download('redis/langcache-embed-v3-small')"

COPY threat_intel_agent ./threat_intel_agent
COPY scripts ./scripts

EXPOSE 8082
CMD ["sh", "-c", "uv run --no-sync uvicorn threat_intel_agent.api:app --host 0.0.0.0 --port ${PORT:-8082} --workers ${WEB_CONCURRENCY:-1}"]
