# A local Hardhat devnet + the deploy/register scripts, packaged for
# docker-compose (see docker-compose.yml at the repo root). Not used for
# real deployments -- those are run by hand with a real RPC/deployer key,
# see scripts/deploy.js's own docs.
FROM node:20-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY hardhat.config.js ./
COPY contracts/ethereum/ ./contracts/ethereum/
COPY scripts/ ./scripts/
COPY docker/bootstrap.js ./docker/bootstrap.js

EXPOSE 8545
