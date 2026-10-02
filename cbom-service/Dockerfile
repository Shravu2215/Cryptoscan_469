# Build context is the repo root so that shared/ is available.
# Build with:  docker build -f cbom-service/Dockerfile -t cryptoscan-cbom-service .
FROM node:20-bookworm-slim

WORKDIR /app

# Copy shared module first (required by src/server.js -> ../../shared/preflight)
COPY shared ./shared

# Install cbom-service dependencies
COPY cbom-service/package.json cbom-service/package-lock.json ./cbom-service/
RUN cd cbom-service && npm ci --omit=dev

# Copy rest of cbom-service source
COPY cbom-service ./cbom-service

WORKDIR /app/cbom-service

ENV NODE_ENV=production
EXPOSE 4003

CMD ["node", "src/server.js"]
