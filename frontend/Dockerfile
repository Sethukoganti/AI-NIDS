# ---------------------------------------------------------------------------
# AI-NIDS frontend image - multi-stage: build with Vite, serve with nginx.
#
# Build context is the *repository root* (see docker-compose.yml) so the
# simulation sample CSVs in ./frontend/public/samples ship with the image.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci

COPY frontend/ ./

# The client always calls the relative /api path (src/lib/api.ts), which nginx
# proxies to the backend container - no build-time API URL is needed.
RUN npm run build


FROM nginx:1.27-alpine AS runtime

ENV TZ=UTC

# SPA routing + /api and /docs proxy to the backend service.
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
