# farpoint in a container. Targets:
#   full (default)  farpoint with every discovery source: dnstwist, subfinder and bbot
#   slim            farpoint and dnstwist only (no subfinder or bbot), about a quarter of the size
#   test            the offline test suite: docker run --rm $(docker build -q --target test .)
# README.md ("Docker") covers running it.

FROM ghcr.io/astral-sh/uv:0.8.17 AS uv

# Built statically: the official subfinder image is Alpine, and its musl binary won't run on Debian.
FROM golang:1.24-bookworm AS subfinder
RUN CGO_ENABLED=0 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.9.0

FROM python:3.12-slim-bookworm AS base
COPY --from=uv /uv /uvx /usr/local/bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev
ENV PATH=/app/.venv/bin:$PATH
# farpoint reads .env from, and writes ./out under, the directory it runs in.
RUN useradd -m -u 1000 scan && mkdir /work && chown scan /work

FROM base AS test
RUN uv sync --frozen
COPY tests ./tests
USER scan
ENTRYPOINT ["python", "-m", "pytest", "-p", "no:cacheprovider"]

FROM base AS slim
USER scan
WORKDIR /work
ENTRYPOINT ["farpoint"]

FROM base AS full
COPY --from=subfinder /go/bin/subfinder /usr/local/bin/subfinder
# bbot installs these "core deps" itself on first run, via sudo and ansible, which the container lacks.
RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip curl git make gcc xz-utils p7zip-full libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# bbot pip-installs module deps into its own venv, so the scan user owns it. Pinned: the warm-up below
# uses bbot's Python API.
ENV UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin
RUN uv tool install --python /usr/local/bin/python3.12 bbot==3.0.2 && chown -R scan /opt/uv-tools/bbot
USER scan
# Set up the modules of the preset farpoint runs (bbot's --dry-run stops before this), so scans don't
# install anything and a module that can't be set up fails the build instead of returning nothing.
RUN /opt/uv-tools/bbot/bin/python -c "\
import asyncio; from bbot.scanner import Scanner; \
s = Scanner('example.com', presets=['subdomain-enum'], require_flags=['passive']); asyncio.run(s._prep()); \
failed = [m for m, ok in s.helpers.depsinstaller.setup_status.items() if ok is False]; \
assert not failed, f'bbot module setup failed: {failed}'"
WORKDIR /work
ENTRYPOINT ["farpoint"]
