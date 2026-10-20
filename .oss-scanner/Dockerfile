# Audit environment built from this checkout, not an already published package.
FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5
ENV CI=1 \
    WRANGLER_SEND_METRICS=false \
    NO_UPDATE_NOTIFIER=1 \
    npm_config_audit=false \
    npm_config_fund=false \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/oss-scanner-venv/bin:$PATH
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv make git jq ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/oss-scanner-venv \
    && python -m pip install --upgrade pip setuptools wheel
WORKDIR /src
COPY . /src
RUN npm ci --no-audit --no-fund \
    && python -m pip install -e "./packages/python-sdk[test,pydantic,httpx]" build \
    && npm run build \
    && python -m build --wheel --no-isolation packages/python-sdk \
    && mkdir -p /tmp/vizier-release-archives \
    && npm pack --workspace @agenda-intelligence/vizier-sdk --pack-destination /tmp/vizier-release-archives \
    && npm pack --workspace @agenda-intelligence/vizier-mcp-proxy --pack-destination /tmp/vizier-release-archives \
    && npm pack --workspace @agenda-intelligence/vizier-gated-deploy --pack-destination /tmp/vizier-release-archives \
    && node scripts/check-release-archives.mjs /tmp/vizier-release-archives \
    && rm -rf /tmp/vizier-release-archives
CMD ["/bin/bash"]
