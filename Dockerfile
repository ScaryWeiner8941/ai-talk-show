FROM node:20-alpine

ENV NODE_ENV=production

# Install runtime dependencies
RUN apk add --no-cache curl

# Create app directory and use non-root user provided by the image
RUN mkdir -p /app

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --omit=dev

# Copy application code
COPY . .

# Ensure logs directory exists with correct ownership
RUN mkdir -p logs && chown -R node:node /app

USER node

# Expose the port the app listens on
EXPOSE 3000

# Healthcheck to verify the service is running
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD curl -fsS http://127.0.0.1:3000/healthz || exit 1

# Start the application
CMD ["npm", "start"]
