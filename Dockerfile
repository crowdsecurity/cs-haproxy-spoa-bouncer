ARG GOVERSION=1.25

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-spoa-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build DOCKER_BUILD=1

FROM alpine:latest
COPY --from=build /go/src/cs-spoa-bouncer/crowdsec-spoa-bouncer /usr/local/bin/crowdsec-spoa-bouncer
COPY --from=build /go/src/cs-spoa-bouncer/config/crowdsec-spoa-bouncer.yaml /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml
COPY --from=build /go/src/cs-spoa-bouncer/docker/docker_start.sh /docker_start.sh

# Set permissions for config file and binary
RUN chmod 644 /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml && \
    chmod 755 /usr/local/bin/crowdsec-spoa-bouncer

## Add the same haproxy user as the official haproxy image
RUN addgroup -g 99 -S haproxy && adduser -S -D -H -u 99 -h /var/lib/haproxy -s /sbin/nologin -G haproxy -g haproxy haproxy
## Add worker user
RUN addgroup -S crowdsec-spoa && adduser -S -D -H -s /sbin/nologin -g crowdsec-spoa crowdsec-spoa

## Create a socket for the spoa to inherit crowdsec-spoa:haproxy user from official haproxy image
RUN mkdir -p /run/crowdsec-spoa/ && chown crowdsec-spoa:haproxy /run/crowdsec-spoa/ && chmod 770 /run/crowdsec-spoa/

## Create log directory with proper permissions
RUN mkdir -p /var/log/crowdsec-spoa && chown crowdsec-spoa:crowdsec-spoa /var/log/crowdsec-spoa && chmod 755 /var/log/crowdsec-spoa

## Copy Lua files (matching Debian/RPM paths)
RUN mkdir -p /usr/lib/crowdsec-haproxy-spoa-bouncer/lua
COPY --from=build /go/src/cs-spoa-bouncer/lua/* /usr/lib/crowdsec-haproxy-spoa-bouncer/lua/

## Copy templates (matching Debian/RPM paths)
RUN mkdir -p /var/lib/crowdsec-haproxy-spoa-bouncer/html
COPY --from=build /go/src/cs-spoa-bouncer/templates/* /var/lib/crowdsec-haproxy-spoa-bouncer/html/

RUN chown -R root:haproxy /usr/lib/crowdsec-haproxy-spoa-bouncer/lua /var/lib/crowdsec-haproxy-spoa-bouncer/html && \
    chmod -R 755 /usr/lib/crowdsec-haproxy-spoa-bouncer/lua /var/lib/crowdsec-haproxy-spoa-bouncer/html
VOLUME [ "/usr/lib/crowdsec-haproxy-spoa-bouncer/lua/", "/var/lib/crowdsec-haproxy-spoa-bouncer/html/" ]

RUN chmod +x /docker_start.sh

# Run as user
USER crowdsec-spoa

ENTRYPOINT ["/docker_start.sh"]
