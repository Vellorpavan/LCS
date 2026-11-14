# Multi-stage container for Living Capability System (LCS)
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy packaging configuration and all source modules for wheel compilation
COPY pyproject.toml README.md ./
COPY *.py ./
COPY *.sql ./
COPY lcs/ ./lcs/

RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir .

# Production runtime image
FROM python:3.12-slim

WORKDIR /app

# Create unprivileged system user
RUN groupadd -g 1000 lcs && \
    useradd -u 1000 -g lcs -s /bin/bash -m lcs && \
    mkdir -p /data/lcs && \
    chown -R lcs:lcs /data/lcs /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/lcs /usr/local/bin/lcs

# Copy application source
COPY --chown=lcs:lcs . /app/

USER lcs

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    LCS_ROOT=/data/lcs \
    PATH="/usr/local/bin:${PATH}"

VOLUME ["/data/lcs"]

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8765/api/status')" || exit 1

ENTRYPOINT ["lcs"]
CMD ["dashboard", "--host", "0.0.0.0", "--port", "8765"]
