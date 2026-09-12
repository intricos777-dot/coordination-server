# Coordination Server Dockerfile
# Multi-stage build for minimal production image

# ─── Build Stage ────────────────────────────────────────────────────

FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev)
RUN npm ci

# Copy source
COPY src/ ./src/

# ─── Production Stage ───────────────────────────────────────────────

FROM node:20-alpine AS production

# Add non-root user
RUN addgroup -g 1000 -S coord && \
    adduser -u 1000 -S coord -G coord

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy built source from builder
COPY --from=builder /app/src ./src

# Create data directories with correct permissions
RUN mkdir -p /app/data/logs /app/data/certs && \
    chown -R coord:coord /app

# Switch to non-root user
USER coord

# Environment variables
ENV NODE_ENV=production \
    COORD_PORT=4126 \
    COORD_LOG_DIR=/app/data/logs \
    COORD_DATA_DIR=/app/data \
    COORD_LOG_LEVEL=info

# Expose ports
EXPOSE 4126

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:4126/health || exit 1

# Start server
CMD ["node", "src/index.js"]