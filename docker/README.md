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
  -e CROWDSEC_KEY=your-api-key \
  -e CROWDSEC_URL=http://crowdsec:8080/ \
  -p 9000:9000 \
  -p 6060:6060 \
  crowdsecurity/spoa-bouncer
```

## Configuration

### Environment Variables

The Docker image uses a configuration file optimized for containers with extensive environment variable support:

| Variable | Default | Description |
|----------|---------|-------------|
| `CROWDSEC_KEY` | *(required)* | API key for CrowdSec LAPI |
| `CROWDSEC_URL` | `http://crowdsec:8080/` | CrowdSec LAPI URL |
| `LOG_MODE` | `stdout` | Log output: `stdout` or `file` |
| `LOG_LEVEL` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `UPDATE_FREQUENCY` | `10s` | How often to poll LAPI for decisions |
| `INSECURE_SKIP_VERIFY` | `false` | Skip TLS verification for LAPI |
| `LISTEN_TCP` | `0.0.0.0:9000` | TCP listener address |
| `LISTEN_UNIX` | *(disabled)* | Unix socket path (uncomment in config) |
| `PROMETHEUS_ENABLED` | `true` | Enable Prometheus metrics |
| `PROMETHEUS_ADDR` | `0.0.0.0` | Prometheus listen address |
| `PROMETHEUS_PORT` | `6060` | Prometheus listen port |
| `APPSEC_URL` | *(disabled)* | AppSec endpoint URL |
| `APPSEC_TIMEOUT` | `200ms` | AppSec request timeout |
| `GOMEMLIMIT` | *(unset)* | Go memory limit (e.g., `200MiB`) |

### Custom Configuration

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/your/config.yaml:/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml:ro \
  -p 9000:9000 \
  crowdsecurity/spoa-bouncer
```

Or specify a different config path:

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/config.yaml:/config.yaml:ro \
  -p 9000:9000 \
  crowdsecurity/spoa-bouncer -c /config.yaml
```

### Unix Socket (Recommended for Same-Host HAProxy)

```bash
docker run -d \
  --name crowdsec-spoa-bouncer \
  -v /path/to/config.yaml:/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml:ro \
  -v /run/crowdsec-spoa:/run/crowdsec-spoa \
  crowdsecurity/spoa-bouncer
```

Ensure the socket directory exists and has appropriate permissions for HAProxy to connect.

## Docker Compose Example

```yaml
services:
  crowdsec-spoa-bouncer:
    image: crowdsecurity/spoa-bouncer
    restart: unless-stopped
    environment:
      - CROWDSEC_KEY=${CROWDSEC_API_KEY}
      - CROWDSEC_URL=http://crowdsec:8080/
      - LOG_LEVEL=info
      - GOMEMLIMIT=200MiB
    ports:
      - "6060:6060"  # Prometheus metrics
    networks:
      - crowdsec
    deploy:
      resources:
        limits:
          memory: 256M

  haproxy:
    image: haproxy:latest
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    ports:
      - "80:80"
      - "443:443"
    networks:
      - crowdsec
    depends_on:
      - crowdsec-spoa-bouncer

networks:
  crowdsec:
```

## Running as Non-Root

The scratch image runs as root by default. To run as a specific user:

```bash
docker run -d \
  --user 1000:1000 \
  --name crowdsec-spoa-bouncer \
  -p 9000:9000 \
  crowdsecurity/spoa-bouncer
```

Note: Ensure mounted volumes have appropriate permissions for the specified user.

## Health Checks

Prometheus metrics are enabled by default on port 6060. Since this is a scratch image with no shell, use external health checks:

```yaml
# Docker Compose with healthcheck via curl sidecar
services:
  crowdsec-spoa-bouncer:
    image: crowdsecurity/spoa-bouncer
    environment:
      - CROWDSEC_KEY=${API_KEY}
    # Use depends_on with service_healthy for dependent services

  healthcheck:
    image: curlimages/curl:latest
    command: ["sh", "-c", "while true; do curl -sf http://crowdsec-spoa-bouncer:6060/metrics > /dev/null && echo healthy || echo unhealthy; sleep 30; done"]
    depends_on:
      - crowdsec-spoa-bouncer
```

Or check from the host:

```bash
curl -sf http://localhost:6060/metrics > /dev/null && echo "healthy" || echo "unhealthy"
```

## Ports

| Port | Default | Description |
|------|---------|-------------|
| 9000 | Yes | SPOA TCP listener |
| 6060 | Yes | Prometheus metrics (enabled by default) |
| 6070 | No | pprof debug endpoint (disabled by default) |

## Troubleshooting

### View Logs

```bash
docker logs -f crowdsec-spoa-bouncer
```

### Debug Mode

Set the `LOG_LEVEL` environment variable:

```bash
docker run -e LOG_LEVEL=debug -e CROWDSEC_KEY=... crowdsecurity/spoa-bouncer
```

### Connection Issues

1. Verify LAPI is reachable from the container
2. Check API key is correct
3. Ensure HAProxy can reach the SPOA listener (TCP port or Unix socket)

## Building the Image

```bash
docker build -t crowdsecurity/spoa-bouncer .
```

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| GOVERSION | 1.25 | Go version for build stage |

