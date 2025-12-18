# CrowdSec HAProxy SPOA Bouncer Docker Image

This is a minimal scratch-based Docker image containing only the statically-linked bouncer binary and essential files.

## Image Contents

```
/crowdsec-spoa-bouncer                              # The bouncer binary
/etc/ssl/certs/ca-certificates.crt                  # CA certs for HTTPS to LAPI
/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml   # Default config
/usr/lib/crowdsec-haproxy-spoa-bouncer/lua/         # Lua files for HAProxy
/var/lib/crowdsec-haproxy-spoa-bouncer/html/        # Ban/captcha templates
```

## Quick Start

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -e API_KEY=your-api-key \
  -p 9000:9000 \
  crowdsec/haproxy-spoa-bouncer
```

## Configuration

### Environment Variables

The default config supports environment variable substitution for `API_KEY`. For other settings, mount a custom config file.

### Custom Configuration

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/your/config.yaml:/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml:ro \
  -p 9000:9000 \
  crowdsec/haproxy-spoa-bouncer
```

Or specify a different config path:

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/config.yaml:/config.yaml:ro \
  -p 9000:9000 \
  crowdsec/haproxy-spoa-bouncer -c /config.yaml
```

### Unix Socket (Recommended for Same-Host HAProxy)

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/config.yaml:/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml:ro \
  -v /run/crowdsec-spoa:/run/crowdsec-spoa \
  crowdsec/haproxy-spoa-bouncer
```

Ensure the socket directory exists and has appropriate permissions for HAProxy to connect.

## Docker Compose Example

```yaml
services:
  crowdsec-spoa-bouncer:
    image: crowdsec/haproxy-spoa-bouncer
    restart: unless-stopped
    environment:
      - API_KEY=${CROWDSEC_API_KEY}
    volumes:
      - ./config/crowdsec-spoa-bouncer.yaml:/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml:ro
      - spoa-socket:/run/crowdsec-spoa
    # Optional: resource limits
    deploy:
      resources:
        limits:
          memory: 256M
    # Optional: set GOMEMLIMIT for better memory management
    # environment:
    #   - GOMEMLIMIT=200MiB

  haproxy:
    image: haproxy:latest
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
      - spoa-socket:/run/crowdsec-spoa
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - crowdsec-spoa-bouncer

volumes:
  spoa-socket:
```

## Running as Non-Root

The scratch image runs as root by default. To run as a specific user:

```bash
docker run -d \
  --user 1000:1000 \
  --name crowdsec-spoa-bouncer \
  -p 9000:9000 \
  crowdsec/haproxy-spoa-bouncer
```

Note: Ensure mounted volumes have appropriate permissions for the specified user.

## Health Checks

The bouncer exposes Prometheus metrics when enabled in config:

```yaml
prometheus:
  enabled: true
  listen_addr: 0.0.0.0
  listen_port: 60601
```

Then use for health checks:

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  --health-cmd="wget -q --spider http://localhost:60601/metrics || exit 1" \
  --health-interval=30s \
  -p 9000:9000 \
  -p 60601:60601 \
  crowdsec/haproxy-spoa-bouncer
```

Note: Since this is a scratch image, `wget` is not available. Use an external health check or a sidecar container for HTTP health probes.

## Ports

| Port | Description |
|------|-------------|
| 9000 | SPOA TCP listener (default) |
| 60601 | Prometheus metrics (when enabled) |
| 6060 | pprof debug endpoint (when enabled) |

## Troubleshooting

### View Logs

```bash
docker logs -f crowdsec-spoa-bouncer
```

### Debug Mode

Set `log_level: debug` in your config file for verbose logging.

### Connection Issues

1. Verify LAPI is reachable from the container
2. Check API key is correct
3. Ensure HAProxy can reach the SPOA listener (TCP port or Unix socket)

## Building the Image

```bash
docker build -t crowdsec/haproxy-spoa-bouncer .
```

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| GOVERSION | 1.25 | Go version for build stage |

