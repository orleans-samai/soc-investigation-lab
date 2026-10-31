FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
# Baked into the rewrites manifest: where the Next server proxies /api requests.
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN addgroup -S soclab && adduser -S soclab -G soclab
COPY --from=build --chown=soclab:soclab /app/.next/standalone ./
COPY --from=build --chown=soclab:soclab /app/.next/static ./.next/static
COPY --from=build --chown=soclab:soclab /app/public ./public
USER soclab
EXPOSE 3000
CMD ["node", "server.js"]
