# Accountable Agents Framework reference implementation: one image, several roles.
#   default command:  the federation (trust anchor, registries, record keepers)
#   relying party:    node src/rp/standalone.js --config <file>
# No dependencies to install: the code uses only Node's standard library.
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY config ./config
COPY scripts ./scripts
COPY src ./src
# Runtime state (generated keys, admin tokens, logs) lives on a volume, never in the image.
RUN mkdir -p /data && chown node:node /data
ENV NODE_ENV=production \
    AAF_DATA_DIR=/data \
    AAF_STARTUP_TIMEOUT_SECONDS=120
VOLUME ["/data"]
EXPOSE 4100 4101 4201 4400
USER node
CMD ["node", "scripts/start.js"]
