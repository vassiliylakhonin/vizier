FROM node:24-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
RUN npm ci --ignore-scripts
COPY tsconfig*.json vitest.config.ts ./
COPY src ./src
COPY tests ./tests
COPY migrations ./migrations
RUN npm run build --workspace @agenda-intelligence/vizier-sdk
ENV VIZIER_ISOLATION_TEST=1
CMD ["npx", "--no-install", "vitest", "run", "tests/worker-version-deploy.test.ts", "--reporter=verbose"]
