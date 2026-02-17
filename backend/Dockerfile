FROM python:3.12-slim AS base

# Security: run as non-root
RUN groupadd -r sentry && useradd -r -g sentry sentry

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into /app/backend/
COPY . /app/backend/

# Create data and watched directories (writable volumes)
RUN mkdir -p /app/data /app/watched && \
    chown -R sentry:sentry /app

USER sentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["python", "-m", "uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
