FROM python:3.12-slim AS base

# Security: run as non-root
RUN groupadd -r sentry && useradd -r -g sentry sentry

# Install git (required by apply_patch tool for safe diff application)
# Install docker-cli only (required by restart_service tool to restart containers via Docker socket)
RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz \
       | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code into /app/backend/
COPY . /app/backend/

# ---------------------------------------------------------------------------
# TEST STAGE — runs at build time; fails the build if any test fails
# Usage (standalone): docker build --target test -t sentry-test ./backend
# ---------------------------------------------------------------------------
FROM base AS test

# Create pytest.ini and .coveragerc inline (avoids Docker context issues)
RUN printf '[pytest]\ntestpaths = backend/tests\nasyncio_mode = auto\npython_files = test_*.py\npython_classes = Test*\npython_functions = test_*\n' > /app/pytest.ini

RUN printf '[run]\nsource = backend\nomit =\n    backend/tests/*\n    */__init__.py\n\n[report]\nshow_missing = True\n' > /app/.coveragerc

# Create data and watched directories needed by test fixtures
RUN mkdir -p /app/data /app/watched/config && \
    printf "DB_HOST = 'localhost'\nDB_PORT = 5432\n" > /app/watched/config/db.py

# Run full test suite with coverage — build fails on test failure or <80% coverage
RUN cd /app && python -m pytest backend/tests/ \
    -v --tb=short \
    --cov=backend --cov-report=term-missing --cov-fail-under=80

# Write a marker file to prove tests passed
RUN echo "TESTS_PASSED" > /app/.tests-passed

# ---------------------------------------------------------------------------
# PRODUCTION STAGE — only reached if tests pass
# The COPY --from=test forces Docker to run the test stage first.
# ---------------------------------------------------------------------------
FROM base AS production

# Force test stage to run — this COPY fails if tests didn't pass
COPY --from=test /app/.tests-passed /tmp/.tests-passed
RUN rm -f /tmp/.tests-passed

# Create data and watched directories (writable volumes)
# Add sentry to root group so it can access Docker socket (mounted at /var/run/docker.sock)
RUN mkdir -p /app/data /app/watched && \
    chown -R sentry:sentry /app && \
    usermod -aG root sentry

USER sentry

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["python", "-m", "uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
