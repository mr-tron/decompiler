FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS toolchains

ARG BUILD_JOBS=4
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates cmake make git g++ libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY toolchains.lock.json ./
COPY scripts/bootstrap.py scripts/bootstrap.py
RUN python scripts/bootstrap.py --root /opt/ton --jobs "${BUILD_JOBS}" \
    && rm -rf /opt/ton/sources

FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TON_TOOLCHAIN_ROOT=/opt/ton \
    TON_CACHE_DIR=/var/cache/decompiler \
    TON_CACHE_MAX_BYTES=536870912
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 libssl3 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 decompiler \
    && useradd --uid 10001 --gid decompiler --no-create-home decompiler \
    && mkdir -p /var/cache/decompiler \
    && chown decompiler:decompiler /var/cache/decompiler
COPY --from=toolchains /opt/ton /opt/ton
COPY toolchains.lock.json ./
COPY decompiler/ decompiler/
COPY scripts/limited_exec.py scripts/limited_exec.py
COPY research/fingerprints.json research/fingerprints.json
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "decompiler", "serve", "--host", "0.0.0.0", "--port", "8080"]
