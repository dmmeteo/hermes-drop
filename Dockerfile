# Hermes Drop broker. Two stages so the browser bundle is built with the dev
# dependency (esbuild) but the runtime image ships production deps only.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src ./src
COPY scripts ./scripts
RUN node scripts/build-client.mjs

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/src ./src
COPY bin ./bin

# The control socket lives in a directory only the broker user can write to.
# There is no admin HTTP endpoint: `docker compose exec` is the admin path.
RUN mkdir -p /run/handoff && chown node:node /run/handoff
USER node

ENV HANDOFF_PORT=8787 \
    HANDOFF_HOST=0.0.0.0 \
    HANDOFF_CONTROL_SOCKET=/run/handoff/control.sock \
    HANDOFF_ENABLE_HSTS=1

EXPOSE 8787

# Absolute path plus an inert marker argument, so this process is unmistakable
# on the *host* process table. A container's argv shows up there verbatim, and
# `npm start` runs `node src/main.js` — byte-identical to the old CMD. That
# collision is not theoretical: a host-side `pkill -f "node src/main.js"` aimed
# at a local dev broker killed this container twice on 2026-08-02. Nothing reads
# the marker; it exists to be seen in `ps` and to make a careless pattern miss.
CMD ["node", "/app/src/main.js", "--role=handoff-broker-container"]
