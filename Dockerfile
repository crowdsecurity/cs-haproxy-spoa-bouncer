ARG GOVERSION=1.25

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-spoa-bouncer

RUN apk add --update --no-cache make git ca-certificates
COPY . .

RUN make build DOCKER_BUILD=1

# Create directory structure for scratch image (with .keep files so COPY works)
RUN mkdir -p /run/crowdsec-spoa /var/log/crowdsec-spoa && \
    touch /run/crowdsec-spoa/.keep /var/log/crowdsec-spoa/.keep

# Final minimal image
FROM scratch

# Default environment variables (can be overridden at runtime)
# CHALLENGE_HTTP_LISTEN defaults to empty (feature disabled) so existing
# deployments that don't set it are unaffected; set it (e.g. 0.0.0.0:9100)
# to enable the AppSec challenge HTTP backend - see docker-compose.yaml.
ENV LOG_MODE=stdout \
    LOG_LEVEL=info \
    CROWDSEC_URL=http://crowdsec:8080/ \
    UPDATE_FREQUENCY=10s \
    INSECURE_SKIP_VERIFY=false \
    LISTEN_TCP=0.0.0.0:9000 \
    CHALLENGE_HTTP_LISTEN= \
    PROMETHEUS_ENABLED=true \
    PROMETHEUS_ADDR=0.0.0.0 \
    PROMETHEUS_PORT=6060

# Copy CA certificates for HTTPS connections to LAPI
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary
COPY --from=build /go/src/cs-spoa-bouncer/crowdsec-spoa-bouncer /crowdsec-spoa-bouncer

# Copy Docker-optimized config file
COPY --from=build /go/src/cs-spoa-bouncer/config/crowdsec-spoa-bouncer.docker.yaml /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml

# Copy optional Lua files for HAProxy installations that enable Lua rendering
COPY --from=build /go/src/cs-spoa-bouncer/lua/ /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/

# Copy HAProxy log-format templates for ban/captcha pages
COPY --from=build /go/src/cs-spoa-bouncer/templates/ /var/lib/crowdsec-haproxy-spoa-bouncer/html/

# Copy runtime directories (required for Unix socket and logs)
COPY --from=build /run/crowdsec-spoa/ /run/crowdsec-spoa/
COPY --from=build /var/log/crowdsec-spoa/ /var/log/crowdsec-spoa/

# Declare volumes for customizable content
VOLUME /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/
VOLUME /var/lib/crowdsec-haproxy-spoa-bouncer/html/

EXPOSE 9000 6060 9100

ENTRYPOINT ["/crowdsec-spoa-bouncer"]
CMD ["-c", "/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml"]
