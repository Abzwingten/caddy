# Use an official lightweight base image
FROM alpine:latest AS builder

# Install dependencies
RUN apk add --no-cache ca-certificates

# Copy the built Caddy binary from the build stage
COPY --from=builder /app/caddy /usr/bin/caddy

# Set the working directory
WORKDIR /etc/caddy

# Expose ports
EXPOSE 80 443

# Run Caddy
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
