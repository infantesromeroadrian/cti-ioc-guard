# syntax=docker/dockerfile:1
# CTI Guard API (research prototype). Offline demo data is baked in; no secrets are baked in.
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 \
    APP_ENV=production DATABASE_URL=sqlite:////data/threat_intel.db
RUN useradd --create-home --uid 1000 appuser && mkdir /data && chown appuser /data
RUN --mount=from=build,source=/wheels,target=/wheels \
    pip install --no-index --find-links=/wheels cti-guard
USER appuser
WORKDIR /home/appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)"
# --demo seeds the database from recorded fixtures (offline). Drop it to start empty.
CMD ["cti-guard", "serve", "--demo", "--host", "0.0.0.0", "--port", "8000"]
