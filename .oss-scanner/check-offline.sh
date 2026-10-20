#!/bin/sh
# Includes only local build/check commands; Wrangler build uses --dry-run.
set -eu
# Refuse registry lookups; archive dependencies were cached during image build.
export npm_config_offline=true
cd /src
npm run check
python -m pytest packages/python-sdk -q
python -m build --wheel --no-isolation packages/python-sdk
mkdir -p /tmp/vizier-release-archives
npm pack --workspace @agenda-intelligence/vizier-sdk --pack-destination /tmp/vizier-release-archives
npm pack --workspace @agenda-intelligence/vizier-mcp-proxy --pack-destination /tmp/vizier-release-archives
npm pack --workspace @agenda-intelligence/vizier-gated-deploy --pack-destination /tmp/vizier-release-archives
node scripts/check-release-archives.mjs /tmp/vizier-release-archives
